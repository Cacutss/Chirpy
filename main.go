package main

import (
	"encoding/json"
	"fmt"
	_ "github.com/lib/pq"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

type apiConfig struct {
	fileserverhits atomic.Int32
}

func (c *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	f := func(writer http.ResponseWriter, req *http.Request) {
		c.fileserverhits.Add(1)
		next.ServeHTTP(writer, req)
	}
	return http.HandlerFunc(f)
}

func (c *apiConfig) Counter(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/html")
	w.WriteHeader(200)
	body := fmt.Sprintf("<html><body><h1>Welcome, Chirpy Admin</h1><p>Chirpy has been visited %d times!</p></body></html>", c.fileserverhits.Load())
	w.Write([]byte(body))
}

func (c *apiConfig) Reset(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	c.fileserverhits.Store(0)
}

func main() {
	const (
		Rootpath = "."
		port     = "8080"
	)
	apiconf := &apiConfig{}
	mux := http.NewServeMux()
	mux.Handle("/app/", apiconf.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(Rootpath)))))
	mux.HandleFunc("GET /api/healthz", Readiness)
	mux.HandleFunc("GET /admin/metrics", apiconf.Counter)
	mux.HandleFunc("POST /admin/reset", apiconf.Reset)
	mux.HandleFunc("POST /api/validate_chirp", validateChirp)
	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}
	go nicemessage()
	log.Fatal(server.ListenAndServe())
}

func nicemessage() {
	dotcount := 3
	dot := "."
	message := "Server listening"
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Printf("%s%s", message, dot)
		if len(dot) == dotcount {
			dot = "."
		} else {
			dot = dot + "."
		}
		time.Sleep(time.Millisecond * 500)
	}
}

func validateChirp(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	defer req.Body.Close()
	reqbody := struct {
		Body string `json:"body"`
	}{}
	err := decoder.Decode(&reqbody)
	if err != nil {
		responseunknownerror(w)
		return
	}
	if len(reqbody.Body) > 140 {
		responsewitherror(w, 400, "Chirp is too long")
		return
	} else {
		cleantext := profanitycheck(reqbody.Body)
		resmessage, err := json.Marshal(struct {
			Cleanedbody string `json:"cleaned_body"`
		}{Cleanedbody: cleantext})
		if err != nil {
			responseunknownerror(w)
			return
		}
		responsewithjson(w, resmessage)
		return
	}
}

func profanitycheck(s string) string {
	badwordlist := []string{"kerfuffle", "sharbert", "fornax"}
	splitted := strings.Split(s, " ")
	for i, str := range splitted {
		normalized := strings.ToLower(str)
		for _, v := range badwordlist {
			if normalized == v {
				splitted[i] = "****"
			}
		}
	}
	return strings.Join(splitted, " ")
}

func responseunknownerror(w http.ResponseWriter) {
	message, _ := json.Marshal(struct {
		Error string `json:"error"`
	}{Error: "Something went wrong"})
	w.WriteHeader(500)
	w.Write(message)
}

func responsewitherror(w http.ResponseWriter, code int, message string) {
	w.Header().Add("Content-Type", "application/json")
	error, _ := json.Marshal(struct {
		Error string `json:"error"`
	}{Error: message})
	w.WriteHeader(code)
	w.Write(error)
}

func responsewithjson(w http.ResponseWriter, data []byte) {
	w.Header().Add("Content-Type", "application/json")
	w.Write(data)
}

func Readiness(w http.ResponseWriter, req *http.Request) {
	header := w.Header()
	header.Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	content := []byte("200 OK")
	w.Write(content)
}
