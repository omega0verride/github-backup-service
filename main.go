package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// --- Security ---

// GetEncryptionKey looks for a MASTER_KEY env var.
// If missing, it uses a fallback (though it logs a warning for production users).
func GetEncryptionKey() []byte {
	key := os.Getenv("BACKUP_MASTER_KEY")
	if key == "" {
		log.Println("WARNING: BACKUP_MASTER_KEY not set. Using insecure default key. Please set this in production.")
		return []byte("a-very-secret-key-32-chars-long!!") // Default fallback
	}

	// Ensure key is exactly 32 bytes for AES-256
	keyBytes := []byte(key)
	if len(keyBytes) > 32 {
		return keyBytes[:32]
	}
	if len(keyBytes) < 32 {
		// Pad with zeros if too short
		padded := make([]byte, 32)
		copy(padded, keyBytes)
		return padded
	}
	return keyBytes
}

var encryptionKey = GetEncryptionKey()

// --- Models ---

type Config struct {
	Username     string `json:"username"`
	PAT          string `json:"pat"` // Stored encrypted in JSON
	BackupPath   string `json:"backup_path"`
	IntervalMins int    `json:"interval_mins"`
}

type RepoStatus struct {
	Name       string    `json:"name"`
	LastBackup time.Time `json:"last_backup"`
	Status     string    `json:"status"` // "Pending", "Syncing", "Success", "Error"
	Error      string    `json:"error"`
}

type AppState struct {
	mu          sync.RWMutex
	Config      Config
	Repos       map[string]*RepoStatus
	Logs        []string
	LastRunTime time.Time
	TriggerChan chan bool
}

var state = &AppState{
	Repos:       make(map[string]*RepoStatus),
	Logs:        []string{"System initialized. MASTER_KEY loaded."},
	TriggerChan: make(chan bool, 1),
}

const configPath = "backup_config.json"

// --- Encryption Helpers ---

func encrypt(text string) (string, error) {
	if text == "" {
		return "", nil
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(text), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(cryptoText string) (string, error) {
	if cryptoText == "" {
		return "", nil
	}
	data, err := base64.StdEncoding.DecodeString(cryptoText)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// --- Logic ---

func (s *AppState) addLog(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	timestamp := time.Now().Format("15:04:05")
	s.Logs = append(s.Logs, fmt.Sprintf("[%s] %s", timestamp, msg))
	if len(s.Logs) > 100 {
		s.Logs = s.Logs[1:]
	}
}

func saveConfig(c Config) error {
	// Encrypt the PAT before writing to disk
	encryptedPat, err := encrypt(c.PAT)
	if err != nil {
		return err
	}
	c.PAT = encryptedPat
	data, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(configPath, data, 0644)
}

func loadConfig() Config {
	var c Config
	data, err := os.ReadFile(configPath)
	if err == nil {
		json.Unmarshal(data, &c)
	} else {
		c.BackupPath = "backups"
		c.IntervalMins = 60
	}
	return c
}

func gitSync(repoName string, cloneURL string, targetDir string) error {
	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		cmd := exec.Command("git", "clone", "--mirror", cloneURL, targetDir)
		return cmd.Run()
	}
	cmd := exec.Command("git", "-C", targetDir, "remote", "update")
	return cmd.Run()
}

func fetchGithubRepos(username, encryptedPat string) ([]string, []string, error) {
	pat, err := decrypt(encryptedPat)
	if err != nil || pat == "" {
		return nil, nil, fmt.Errorf("invalid or missing PAT")
	}

	url := "https://api.github.com/user/repos?per_page=100&sort=updated"
	req, _ := http.NewRequest("GET", url, nil)
	req.SetBasicAuth(username, pat)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("GitHub API Error: %s", resp.Status)
	}

	var data []struct {
		Name     string `json:"name"`
		CloneURL string `json:"clone_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, nil, err
	}

	names := make([]string, len(data))
	urls := make([]string, len(data))
	for i, r := range data {
		names[i] = r.Name
		urls[i] = r.CloneURL
	}
	return names, urls, nil
}

func backupWorker() {
	for {
		state.mu.RLock()
		conf := state.Config
		state.mu.RUnlock()

		if conf.Username != "" && conf.PAT != "" {
			state.addLog("Cycle starting...")
			names, urls, err := fetchGithubRepos(conf.Username, conf.PAT)

			if err != nil {
				state.addLog("Fetch failed: " + err.Error())
			} else {
				os.MkdirAll(conf.BackupPath, 0755)
				decryptedPat, _ := decrypt(conf.PAT)

				for i, name := range names {
					state.mu.Lock()
					if _, ok := state.Repos[name]; !ok {
						state.Repos[name] = &RepoStatus{Name: name, Status: "Pending"}
					}
					repo := state.Repos[name]
					repo.Status = "Syncing"
					state.mu.Unlock()

					target := filepath.Join(conf.BackupPath, name+".git")
					// Use the decrypted PAT for the Git URL
					authURL := fmt.Sprintf("https://%s:%s@%s", conf.Username, decryptedPat, urls[i][8:])

					syncErr := gitSync(name, authURL, target)

					state.mu.Lock()
					repo.LastBackup = time.Now()
					if syncErr != nil {
						repo.Status = "Error"
						repo.Error = syncErr.Error()
					} else {
						repo.Status = "Success"
						repo.Error = ""
					}
					state.mu.Unlock()
				}
			}
			state.mu.Lock()
			state.LastRunTime = time.Now()
			state.mu.Unlock()
			state.addLog("Cycle finished.")
		}

		state.mu.RLock()
		mins := state.Config.IntervalMins
		state.mu.RUnlock()

		if mins <= 0 {
			mins = 60
		}

		select {
		case <-state.TriggerChan:
			state.addLog("Manual sync initiated.")
		case <-time.After(time.Duration(mins) * time.Minute):
		}
	}
}

// --- Handlers ---

func handleIndex(w http.ResponseWriter, r *http.Request) {
	state.mu.RLock()
	defer state.mu.RUnlock()
	viewState := *state
	viewState.Config.PAT = "" // Security: Never send to UI
	tmpl := template.Must(template.New("index").Parse(htmlTemplate))
	tmpl.Execute(w, viewState)
}

func handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	r.ParseForm()

	newPat := r.FormValue("pat")

	state.mu.RLock()
	currentEncryptedPat := state.Config.PAT
	state.mu.RUnlock()

	// If the user didn't enter a new PAT, keep the one we already have
	finalPat := newPat
	if newPat == "" && currentEncryptedPat != "" {
		decrypted, err := decrypt(currentEncryptedPat)
		if err == nil {
			finalPat = decrypted
		}
	}

	newConfig := Config{
		Username:     r.FormValue("username"),
		PAT:          finalPat,
		BackupPath:   r.FormValue("backup_path"),
		IntervalMins: 60,
	}
	if m, err := strconv.Atoi(r.FormValue("interval_mins")); err == nil {
		newConfig.IntervalMins = m
	}

	// Update state with newly encrypted version
	encPat, _ := encrypt(newConfig.PAT)
	state.mu.Lock()
	state.Config = newConfig
	state.Config.PAT = encPat
	state.mu.Unlock()

	saveConfig(newConfig)
	state.addLog("Configuration updated safely.")

	select {
	case state.TriggerChan <- true:
	default:
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleTrigger(w http.ResponseWriter, r *http.Request) {
	select {
	case state.TriggerChan <- true:
	default:
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func main() {
	state.Config = loadConfig()
	go backupWorker()

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/config", handleUpdateConfig)
	http.HandleFunc("/trigger", handleTrigger)

	fmt.Println("Server active on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

const htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Git Backup Manager</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .log-container { height: 250px; overflow-y: auto; font-family: 'Courier New', Courier, monospace; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-thumb { background: #4f46e5; border-radius: 10px; }
    </style>
</head>
<body class="bg-slate-50 text-slate-900 font-sans">
    <div class="max-w-6xl mx-auto p-4 md:p-8">
        <header class="flex flex-col md:flex-row justify-between items-start md:items-center mb-10 gap-4">
            <div>
                <h1 class="text-3xl font-extrabold text-indigo-700 tracking-tight">Git Mirror</h1>
                <p class="text-slate-500 font-medium">Secure automated local backups for GitHub.</p>
            </div>
            <form action="/trigger" method="POST">
                <button type="submit" class="bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-2.5 rounded-lg font-bold shadow-sm transition flex items-center gap-2">
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M4 2a1 1 0 011 1v2.101a7.002 7.002 0 0111.601 2.566 1 1 0 11-1.885.666A5.002 5.002 0 005.999 7H9a1 1 0 010 2H4a1 1 0 01-1-1V3a1 1 0 011-1zm.008 9.057a1 1 0 011.276.61A5.002 5.002 0 0014.001 13H11a1 1 0 110-2h5a1 1 0 011 1v5a1 1 0 11-2 0v-2.101a7.002 7.002 0 01-11.601-2.566 1 1 0 01.61-1.276z" clip-rule="evenodd" />
                    </svg>
                    Sync All Now
                </button>
            </form>
        </header>

        <div class="grid grid-cols-1 lg:grid-cols-12 gap-8">
            <!-- Sidebar / Settings -->
            <div class="lg:col-span-4">
                <div class="bg-white border border-slate-200 rounded-xl shadow-sm overflow-hidden">
                    <div class="bg-slate-50 p-4 border-b border-slate-200">
                        <h2 class="font-bold text-slate-700 flex items-center gap-2">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                                <path fill-rule="evenodd" d="M11.49 3.17c-.38-1.56-2.6-1.56-2.98 0a1.532 1.532 0 01-2.286.948c-1.372-.836-2.942.734-2.106 2.106.54.886.061 2.042-.947 2.287-1.561.379-1.561 2.6 0 2.978a1.532 1.532 0 01.947 2.287c-.836 1.372.734 2.942 2.106 2.106a1.532 1.532 0 012.287.947c.379 1.561 2.6 1.561 2.978 0a1.533 1.533 0 012.287-.947c1.372.836 2.942-.734 2.106-2.106a1.533 1.533 0 01.947-2.287c1.561-.379 1.561-2.6 0-2.978a1.532 1.532 0 01-.947-2.287c.836-1.372-.734-2.942-2.106-2.106a1.532 1.532 0 01-2.287-.947zM10 13a3 3 0 100-6 3 3 0 000 6z" clip-rule="evenodd" />
                            </svg>
                            Settings
                        </h2>
                    </div>
                    <form action="/config" method="POST" class="p-6 space-y-5">
                        <div>
                            <label class="block text-sm font-bold text-slate-600 mb-1">GitHub Username</label>
                            <input type="text" name="username" value="{{.Config.Username}}" class="w-full border border-slate-300 rounded-lg p-2.5 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none transition" required>
                        </div>
                        <div>
                            <label class="block text-sm font-bold text-slate-600 mb-1">New PAT (Optional)</label>
                            <input type="password" name="pat" class="w-full border border-slate-300 rounded-lg p-2.5 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none transition" placeholder="Keep current token">
                        </div>
                        <div>
                            <label class="block text-sm font-bold text-slate-600 mb-1">Local Storage Path</label>
                            <input type="text" name="backup_path" value="{{.Config.BackupPath}}" class="w-full border border-slate-300 rounded-lg p-2.5 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none transition" required>
                        </div>
                        <div>
                            <label class="block text-sm font-bold text-slate-600 mb-1">Interval (Minutes)</label>
                            <input type="number" name="interval_mins" value="{{.Config.IntervalMins}}" class="w-full border border-slate-300 rounded-lg p-2.5 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none transition" required>
                        </div>
                        <button type="submit" class="w-full bg-slate-800 text-white font-bold py-3 rounded-lg hover:bg-slate-900 shadow-md transition transform active:scale-[0.98]">
                            Save Encrypted Config
                        </button>
                    </form>
                    <div class="px-6 pb-6">
                        <div class="p-3 bg-amber-50 rounded-lg border border-amber-100">
                            <p class="text-[11px] text-amber-800 leading-tight"><b>Pro Tip:</b> Set <code>BACKUP_MASTER_KEY</code> env var to protect your local config file.</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Main Content -->
            <div class="lg:col-span-8 space-y-8">
                <div class="bg-white border border-slate-200 rounded-xl shadow-sm overflow-hidden">
                    <div class="bg-slate-50 p-4 border-b border-slate-200 flex justify-between items-center">
                        <h2 class="font-bold text-slate-700">Repositories</h2>
                        <div class="text-[10px] font-bold text-slate-400 uppercase tracking-widest">
                            Last Run: {{if .LastRunTime.IsZero}}Never{{else}}{{.LastRunTime.Format "15:04:05"}}{{end}}
                        </div>
                    </div>
                    <div class="max-h-[400px] overflow-y-auto">
                        <table class="w-full text-left border-collapse">
                            <thead class="sticky top-0 bg-white shadow-sm z-10">
                                <tr class="text-slate-400 text-[10px] uppercase tracking-widest border-b">
                                    <th class="p-4 font-bold">Repository Name</th>
                                    <th class="p-4 font-bold text-center">Last Synced</th>
                                    <th class="p-4 font-bold text-right">Status</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-slate-100">
                                {{range .Repos}}
                                <tr class="hover:bg-slate-50 transition-colors">
                                    <td class="p-4">
                                        <div class="font-bold text-slate-700">{{.Name}}</div>
                                    </td>
                                    <td class="p-4 text-center text-sm text-slate-500">
                                        {{if .LastBackup.IsZero}}Never{{else}}{{.LastBackup.Format "Jan 02, 15:04"}}{{end}}
                                    </td>
                                    <td class="p-4 text-right">
                                        {{if eq .Status "Success"}}
                                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-100 text-emerald-800">
                                                <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 mr-1.5"></span> OK
                                            </span>
                                        {{else if eq .Status "Syncing"}}
                                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold bg-blue-100 text-blue-800 animate-pulse">
                                                <span class="w-1.5 h-1.5 rounded-full bg-blue-500 mr-1.5"></span> SYNCING
                                            </span>
                                        {{else if eq .Status "Error"}}
                                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-100 text-rose-800" title="{{.Error}}">
                                                <span class="w-1.5 h-1.5 rounded-full bg-rose-500 mr-1.5"></span> FAILED
                                            </span>
                                        {{else}}
                                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold bg-slate-100 text-slate-500">
                                                WAITING
                                            </span>
                                        {{end}}
                                    </td>
                                </tr>
                                {{else}}
                                <tr>
                                    <td colspan="3" class="p-12 text-center">
                                        <div class="text-slate-300 mb-3">
                                            <svg xmlns="http://www.w3.org/2000/svg" class="h-12 w-12 mx-auto" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
                                            </svg>
                                        </div>
                                        <p class="text-slate-400 font-medium italic">No repositories synchronized yet. Configure and trigger a sync to start.</p>
                                    </td>
                                </tr>
                                {{end}}
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Logs Area -->
                <div class="bg-slate-900 rounded-xl shadow-lg overflow-hidden">
                    <div class="flex items-center justify-between px-4 py-2 bg-slate-800 border-b border-slate-700">
                        <span class="text-[10px] font-black text-slate-400 uppercase tracking-widest">System Logs</span>
                        <div class="flex gap-1.5">
                            <div class="w-2 h-2 rounded-full bg-rose-500/50"></div>
                            <div class="w-2 h-2 rounded-full bg-amber-500/50"></div>
                            <div class="w-2 h-2 rounded-full bg-emerald-500/50"></div>
                        </div>
                    </div>
                    <div class="log-container p-4 text-emerald-400 text-xs leading-relaxed" id="logBox">
                        {{range .Logs}}
                        <div class="flex gap-3 mb-1">
                            <span class="text-slate-600 shrink-0 font-bold select-none">></span>
                            <span>{{.}}</span>
                        </div>
                        {{end}}
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const logBox = document.getElementById('logBox');
        if (logBox) logBox.scrollTop = logBox.scrollHeight;
        // Refresh every 30 seconds to update status
        setTimeout(() => { location.reload(); }, 30000);
    </script>
</body>
</html>
`
