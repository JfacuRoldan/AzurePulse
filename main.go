package main

import (
    "bytes"
    "crypto/rand"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "net"
    "net/http"
    "os"
    "strconv"
    "strings"
    "sync"
    "time"
)

// Simple API logger server
// - POST /login accepts JSON payload with client metadata
// - Adds server metadata (ip, timestamp, uuid)
// - Masks sensitive fields (e.g., password, token) recursively
// - Appends one JSON object per line to logs.jsonl
// - Sends short notifications to Discord webhook and Telegram bot
// - Rate limits by IP

// ---------------------------
// Configuration & .env loader
// ---------------------------

type AppConfig struct {
    DiscordWebhookURL string
    TelegramBotToken  string
    TelegramChatID    string
    RateLimit         int           // requests per window
    RateWindow        time.Duration // window duration
}

// loadDotEnv loads a basic .env file from the given path into the process environment.
// Supports: KEY=value with optional surrounding quotes. Lines starting with # are ignored.
func loadDotEnv(path string) error {
    f, err := os.Open(path)
    if err != nil {
        // Silently ignore if file is missing
        if errors.Is(err, os.ErrNotExist) {
            return nil
        }
        return err
    }
    defer f.Close()

    data, err := io.ReadAll(f)
    if err != nil {
        return err
    }
    lines := strings.Split(string(data), "\n")
    for _, line := range lines {
        line = strings.TrimSpace(line)
        if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
            continue
        }
        // Allow export KEY=VALUE
        if strings.HasPrefix(line, "export ") {
            line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
        }
        // Split on first '='
        idx := strings.IndexRune(line, '=')
        if idx <= 0 {
            continue
        }
        key := strings.TrimSpace(line[:idx])
        val := strings.TrimSpace(line[idx+1:])
        // Remove optional quotes
        if len(val) >= 2 {
            if (val[0] == '\'' && val[len(val)-1] == '\'') || (val[0] == '"' && val[len(val)-1] == '"') {
                val = val[1 : len(val)-1]
            }
        }
        _ = os.Setenv(key, val)
    }
    return nil
}

func getenv(key, def string) string {
    if v := os.Getenv(key); v != "" {
        return v
    }
    return def
}

// -----------------
// Rate limit by IP
// -----------------

type visitor struct {
    count   int
    resetAt time.Time
}

type RateLimiter struct {
    mu       sync.Mutex
    visitors map[string]*visitor
    limit    int
    window   time.Duration
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
    return &RateLimiter{
        visitors: make(map[string]*visitor),
        limit:    limit,
        window:   window,
    }
}

// Allow returns whether the request is allowed for the given IP and the time until reset.
func (rl *RateLimiter) Allow(ip string) (bool, time.Duration) {
    now := time.Now()
    rl.mu.Lock()
    defer rl.mu.Unlock()

    v, ok := rl.visitors[ip]
    if !ok || now.After(v.resetAt) {
        rl.visitors[ip] = &visitor{count: 1, resetAt: now.Add(rl.window)}
        return true, rl.window
    }

    if v.count < rl.limit {
        v.count++
        return true, time.Until(v.resetAt)
    }
    return false, time.Until(v.resetAt)
}

// ------------------
// Sensitive masking
// ------------------

var sensitiveKeys = map[string]struct{}{
    "password":      {},
    "pass":          {},
    "pwd":           {},
    "token":         {},
    "auth":          {},
    "authorization": {},
    "apikey":        {},
    "api_key":       {},
    "api-key":       {},
    "secret":        {},
    "refresh_token": {},
}

func isSensitiveKey(k string) bool {
    _, ok := sensitiveKeys[strings.ToLower(k)]
    return ok
}

func maskValue(_ interface{}) interface{} {
    return "[redacted]"
}

// maskSensitive walks the structure and redacts sensitive fields in-place.
func maskSensitive(v interface{}) interface{} {
    switch t := v.(type) {
    case map[string]interface{}:
        for k, val := range t {
            if isSensitiveKey(k) {
                t[k] = maskValue(val)
            } else {
                t[k] = maskSensitive(val)
            }
        }
        return t
    case []interface{}:
        for i := range t {
            t[i] = maskSensitive(t[i])
        }
        return t
    default:
        return v
    }
}

// -----------------
// Utility functions
// -----------------

func getClientIP(r *http.Request) string {
    // Prefer X-Forwarded-For if present
    if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
        parts := strings.Split(xff, ",")
        if len(parts) > 0 {
            ip := strings.TrimSpace(parts[0])
            if ip != "" {
                return ip
            }
        }
    }
    if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
        return strings.TrimSpace(xrip)
    }
    host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
    if err == nil && host != "" {
        return host
    }
    return r.RemoteAddr
}

func uuidV4() (string, error) {
    var b [16]byte
    if _, err := rand.Read(b[:]); err != nil {
        return "", err
    }
    b[6] = (b[6] & 0x0f) | 0x40 // Version 4
    b[8] = (b[8] & 0x3f) | 0x80 // Variant RFC 4122
    // Format xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
        b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
    w.Header().Set("Content-Type", "application/json; charset=utf-8")
    w.WriteHeader(status)
    _ = json.NewEncoder(w).Encode(v)
}

// -----------------
// JSONL file append
// -----------------

var (
    logFilePath = "logs.jsonl"
    logMu       sync.Mutex
)

func appendJSONLine(path string, v interface{}) error {
    logMu.Lock()
    defer logMu.Unlock()

    f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
    if err != nil {
        return err
    }
    defer f.Close()

    enc := json.NewEncoder(f)
    // No pretty-printing for JSONL; one compact object per line
    return enc.Encode(v)
}

// -------------------------
// Discord/Telegram sending
// -------------------------

func sendDiscord(webhookURL, content string, client *http.Client) error {
    if webhookURL == "" {
        return nil
    }
    payload := map[string]string{"content": content}
    body, _ := json.Marshal(payload)
    req, err := http.NewRequest(http.MethodPost, webhookURL, bytes.NewReader(body))
    if err != nil {
        return err
    }
    req.Header.Set("Content-Type", "application/json")
    resp, err := client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    // Discord webhooks often return 204 No Content on success
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
        return fmt.Errorf("discord webhook failed: %d %s", resp.StatusCode, string(b))
    }
    return nil
}

func sendTelegram(token, chatID, content string, client *http.Client) error {
    if token == "" || chatID == "" {
        return nil
    }
    url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
    payload := map[string]interface{}{
        "chat_id":                chatID,
        "text":                   content,
        "disable_web_page_preview": true,
    }
    body, _ := json.Marshal(payload)
    req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
    if err != nil {
        return err
    }
    req.Header.Set("Content-Type", "application/json")
    resp, err := client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
        return fmt.Errorf("telegram sendMessage failed: %d %s", resp.StatusCode, string(b))
    }
    return nil
}

func composeBriefMessage(username, ip, platform, lang string, screenW, screenH int, timestamp string) string {
    var b strings.Builder
    b.WriteString("Nouvelle connexion :\n")
    if username != "" {
        b.WriteString("- user: ")
        b.WriteString(username)
        b.WriteString("\n")
    }
    if ip != "" {
        b.WriteString("- ip: ")
        b.WriteString(ip)
        b.WriteString("\n")
    }
    if platform != "" {
        b.WriteString("- os: ")
        b.WriteString(platform)
        b.WriteString("\n")
    }
    if lang != "" {
        b.WriteString("- lang: ")
        b.WriteString(lang)
        b.WriteString("\n")
    }
    if screenW > 0 && screenH > 0 {
        b.WriteString("- screen: ")
        b.WriteString(strconv.Itoa(screenW))
        b.WriteString("x")
        b.WriteString(strconv.Itoa(screenH))
        b.WriteString("\n")
    }
    if timestamp != "" {
        b.WriteString("- time: ")
        b.WriteString(timestamp)
        b.WriteString("\n")
    }
    return b.String()
}

// -----------------
// HTTP handlers
// -----------------

type server struct {
    cfg      AppConfig
    limiter  *RateLimiter
    httpc    *http.Client
    maxBytes int64
}

func (s *server) loginHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
        return
    }

    ip := getClientIP(r)

    // Limit request body to a reasonable size (1 MiB)
    r.Body = http.MaxBytesReader(w, r.Body, s.maxBytes)
    defer r.Body.Close()

    var payload map[string]interface{}
    dec := json.NewDecoder(r.Body)
    if err := dec.Decode(&payload); err != nil {
        writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
        return
    }

    // Mask sensitive fields
    payload = maskSensitive(payload).(map[string]interface{})

    // Server metadata
    ts := time.Now().UTC().Format(time.RFC3339)
    id, err := uuidV4()
    if err != nil {
        // Fallback to timestamp-based id if crypto/rand fails
        id = fmt.Sprintf("fallback-%d", time.Now().UnixNano())
    }

    // Extract fields for notification (if present)
    username := getString(payload, "username")
    device := getMap(payload, "device")
    platform := getString(device, "platform")
    lang := getString(device, "language")
    screen := getMap(device, "screen")
    sw := toInt(screen["width"]) // may be nil
    sh := toInt(screen["height"])

    // Build log entry
    logEntry := map[string]interface{}{
        "id":        id,
        "timestamp": ts,
        "ip":        ip,
        "path":      "/login",
        "method":    r.Method,
        "client":    payload,
    }

    if err := appendJSONLine(logFilePath, logEntry); err != nil {
        // Fail softly: log to stderr, respond 500
        fmt.Fprintf(os.Stderr, "failed to write log: %v\n", err)
        writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
        return
    }

    // Send notifications (best-effort)
    msg := composeBriefMessage(username, ip, platform, lang, sw, sh, ts)
    go func() {
        if err := sendDiscord(s.cfg.DiscordWebhookURL, msg, s.httpc); err != nil {
            fmt.Fprintf(os.Stderr, "discord notify error: %v\n", err)
        }
    }()
    go func() {
        if err := sendTelegram(s.cfg.TelegramBotToken, s.cfg.TelegramChatID, msg, s.httpc); err != nil {
            fmt.Fprintf(os.Stderr, "telegram notify error: %v\n", err)
        }
    }()

    // Respond to client
    writeJSON(w, http.StatusOK, map[string]interface{}{
        "status":    "ok",
        "id":        id,
        "timestamp": ts,
    })
}

// rateLimitMiddleware enforces per-IP limits before reaching the handler
func (s *server) rateLimitMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        ip := getClientIP(r)
        allowed, retryIn := s.limiter.Allow(ip)
        if !allowed {
            // RFC-compliant Retry-After (seconds)
            secs := int(retryIn.Seconds())
            if secs < 1 {
                secs = 1
            }
            w.Header().Set("Retry-After", strconv.Itoa(secs))
            writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
                "error":          "too_many_requests",
                "retry_after_sec": secs,
            })
            return
        }
        next.ServeHTTP(w, r)
    })
}

// Helpers to safely extract typed values from generic maps
func getMap(m map[string]interface{}, key string) map[string]interface{} {
    if m == nil {
        return map[string]interface{}{}
    }
    if v, ok := m[key]; ok {
        if mm, ok2 := v.(map[string]interface{}); ok2 {
            return mm
        }
    }
    return map[string]interface{}{}
}

func getString(m map[string]interface{}, key string) string {
    if m == nil {
        return ""
    }
    if v, ok := m[key]; ok {
        switch vv := v.(type) {
        case string:
            return vv
        case fmt.Stringer:
            return vv.String()
        default:
            // Attempt JSON stringify for primitive types
            if b, err := json.Marshal(v); err == nil {
                // remove quotes if it was a JSON string
                s := string(b)
                s = strings.TrimPrefix(s, "\"")
                s = strings.TrimSuffix(s, "\"")
                return s
            }
        }
    }
    return ""
}

func toInt(v interface{}) int {
    switch t := v.(type) {
    case float64:
        return int(t)
    case int:
        return t
    case int64:
        return int(t)
    case json.Number:
        i, _ := t.Int64()
        return int(i)
    case string:
        if i, err := strconv.Atoi(t); err == nil {
            return i
        }
    }
    return 0
}

// -----------------
// main: bootstrap
// -----------------

func main() {
    // Load .env if present
    _ = loadDotEnv(".env")

    // Config from env
    cfg := AppConfig{
        DiscordWebhookURL: getenv("DISCORD_WEBHOOK_URL", ""),
        TelegramBotToken:  getenv("TELEGRAM_BOT_TOKEN", ""),
        TelegramChatID:    getenv("TELEGRAM_CHAT_ID", ""),
        RateLimit:         5,
        RateWindow:        time.Minute,
    }

    if v := getenv("RATE_LIMIT", ""); v != "" {
        if n, err := strconv.Atoi(v); err == nil && n > 0 {
            cfg.RateLimit = n
        }
    }
    if v := getenv("RATE_WINDOW_SECONDS", ""); v != "" {
        if n, err := strconv.Atoi(v); err == nil && n > 0 {
            cfg.RateWindow = time.Duration(n) * time.Second
        }
    }

    srv := &server{
        cfg:     cfg,
        limiter: NewRateLimiter(cfg.RateLimit, cfg.RateWindow),
        httpc: &http.Client{
            Timeout: 5 * time.Second,
        },
        maxBytes: 1 << 20, // 1 MiB
    }

    mux := http.NewServeMux()

    // Health endpoint (optional)
    mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
    })

    // /login with rate limiting
    login := http.HandlerFunc(srv.loginHandler)
    mux.Handle("/login", srv.rateLimitMiddleware(login))

    httpSrv := &http.Server{
        Addr:         ":8080",
        Handler:      mux,
        ReadTimeout:  10 * time.Second,
        WriteTimeout: 15 * time.Second,
        IdleTimeout:  60 * time.Second,
    }

    fmt.Println("API logger server listening on http://localhost:8080 …")
    if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
        fmt.Fprintf(os.Stderr, "server error: %v\n", err)
        os.Exit(1)
    }
}

