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

const BackupPath = "./backups"
const configPath = "backup_config.json"
const templatePath = "templates/index.html"

var encryptionKey = GetEncryptionKey()

func GetEncryptionKey() []byte {
	key := os.Getenv("BACKUP_MASTER_KEY")
	if key == "" {
		panic("critical configuration error: BACKUP_MASTER_KEY environment variable is not set")
	}
	keyBytes := []byte(key)
	// Enforce strict 32-byte length (AES-256 requirement)
	if len(keyBytes) != 32 {
		panic(fmt.Sprintf("critical security error: BACKUP_MASTER_KEY must be exactly 32 bytes; got %d", len(keyBytes)))
	}
	return keyBytes
}

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

// --- Models & State ---

type Config struct {
	Username     string `json:"username"`
	PAT          string `json:"pat"`
	IntervalMins int    `json:"interval_mins"`
}

type RepoStatus struct {
	Name       string    `json:"name"`
	LastBackup time.Time `json:"last_backup"`
	Status     string    `json:"status"`
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
	Logs:        []string{"System initialized. Awaiting configuration..."},
	TriggerChan: make(chan bool, 1),
}

// --- Logic ---

func (s *AppState) addLog(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Logs = append(s.Logs, fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg))
	if len(s.Logs) > 100 {
		s.Logs = s.Logs[1:]
	}
}

func loadConfig() Config {
	var c Config
	data, err := os.ReadFile(configPath)
	if err == nil {
		json.Unmarshal(data, &c)
	} else {
		c.IntervalMins = 60
	}
	return c
}

func saveConfig(c Config) error {
	encryptedPat, err := encrypt(c.PAT)
	if err != nil {
		return err
	}
	c.PAT = encryptedPat
	data, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(configPath, data, 0644)
}

func gitSync(cloneURL, targetDir string) error {
	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		return exec.Command("git", "clone", "--mirror", cloneURL, targetDir).Run()
	}
	return exec.Command("git", "-C", targetDir, "remote", "update").Run()
}

func fetchGithubRepos(username, encryptedPat string) ([]string, []string, error) {
	pat, err := decrypt(encryptedPat)
	if err != nil || pat == "" {
		return nil, nil, fmt.Errorf("PAT missing or decryption failed")
	}

	req, _ := http.NewRequest("GET", "https://api.github.com/user/repos?per_page=100&sort=updated", nil)
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
	json.NewDecoder(resp.Body).Decode(&data)

	names, urls := make([]string, len(data)), make([]string, len(data))
	for i, r := range data {
		names[i], urls[i] = r.Name, r.CloneURL
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
				os.MkdirAll(BackupPath, 0755)
				decryptedPat, _ := decrypt(conf.PAT)

				for i, name := range names {
					state.mu.Lock()
					if _, ok := state.Repos[name]; !ok {
						state.Repos[name] = &RepoStatus{Name: name, Status: "Pending"}
					}
					repo := state.Repos[name]
					repo.Status = "Syncing"
					state.mu.Unlock()

					authURL := fmt.Sprintf("https://%s:%s@%s", conf.Username, decryptedPat, urls[i][8:])
					target := filepath.Join(BackupPath, name+".git")

					syncErr := gitSync(authURL, target)

					state.mu.Lock()
					repo.LastBackup = time.Now()
					if syncErr != nil {
						repo.Status = "Error"
						repo.Error = syncErr.Error()
						state.addLog("Sync failed: " + name)
					} else {
						repo.Status = "Success"
						repo.Error = ""
					}
					state.mu.Unlock()
				}
				state.mu.Lock()
				state.LastRunTime = time.Now()
				state.mu.Unlock()
				state.addLog("Cycle complete.")
			}
		}

		state.mu.RLock()
		mins := state.Config.IntervalMins
		if mins < 1 {
			mins = 60
		}
		state.mu.RUnlock()

		select {
		case <-state.TriggerChan:
			state.addLog("Manual trigger received.")
		case <-time.After(time.Duration(mins) * time.Minute):
		}
	}
}

// --- Handlers ---

func handleIndex(w http.ResponseWriter, r *http.Request) {
	state.mu.RLock()
	defer state.mu.RUnlock()

	viewState := *state
	viewState.Config.PAT = ""

	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		http.Error(w, "Could not find index.html in the current directory.", 404)
		return
	}
	tmpl.Execute(w, viewState)
}

func handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	r.ParseForm()

	newPat := r.FormValue("pat")
	state.mu.RLock()
	currentEncrypted := state.Config.PAT
	state.mu.RUnlock()

	finalPat := newPat
	if newPat == "" && currentEncrypted != "" {
		decrypted, _ := decrypt(currentEncrypted)
		finalPat = decrypted
	}

	newConfig := Config{
		Username: r.FormValue("username"),
		PAT:      finalPat,
	}
	newConfig.IntervalMins, _ = strconv.Atoi(r.FormValue("interval_mins"))

	saveConfig(newConfig)

	enc, _ := encrypt(newConfig.PAT)
	state.mu.Lock()
	state.Config = newConfig
	state.Config.PAT = enc
	state.mu.Unlock()

	select {
	case state.TriggerChan <- true:
	default:
	}

	http.Redirect(w, r, "/", 303)
}

func main() {
	state.Config = loadConfig()
	go backupWorker()

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/config", handleUpdateConfig)
	http.HandleFunc("/trigger", func(w http.ResponseWriter, r *http.Request) {
		select {
		case state.TriggerChan <- true:
		default:
		}
		http.Redirect(w, r, "/", 303)
	})

	log.Println("Server running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
