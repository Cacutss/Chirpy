package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	auth "github.com/Cacutss/Chirpy/internal/auth"
	database "github.com/Cacutss/Chirpy/internal/database"
	"github.com/google/uuid"
	godotenv "github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

type apiConfig struct {
	fileserverhits atomic.Int32
	db             *database.Queries
	platform       string
	secret         string
	polkakey       string
}

type WebHook struct {
	Event string `json:"event"`
	Data  struct {
		UserID uuid.UUID `json:"user_id"`
	} `json:"data"`
}

type ParseUser struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
	Password  string    `json:"password"`
	ExpiresIn int       `json:"expires_in_seconds"`
}

type ReturnUser struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserId    uuid.UUID `json:"user_id"`
}

func main() {
	apiconf := &apiConfig{}
	godotenv.Load(".env")
	dbUrl := os.Getenv("DB_URL")
	apiconf.platform = os.Getenv("PLATFORM")
	apiconf.secret = os.Getenv("SECRET")
	apiconf.polkakey = os.Getenv("POLKA_KEY")
	db, err := sql.Open("postgres", dbUrl)
	if err != nil {
		log.Printf("%v", err)
	}
	apiconf.db = database.New(db)
	const (
		Rootpath = "."
		port     = "8080"
	)
	mux := http.NewServeMux()
	mux.Handle("/app/", apiconf.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(Rootpath)))))
	mux.HandleFunc("GET /api/healthz", Readiness)
	mux.HandleFunc("GET /admin/metrics", apiconf.Counter)
	mux.HandleFunc("POST /admin/reset", apiconf.Reset)
	mux.HandleFunc("POST /api/users", apiconf.createUser)
	mux.HandleFunc("PUT /api/users", apiconf.updateuser)
	mux.HandleFunc("POST /api/login", apiconf.login)
	mux.HandleFunc("POST /api/refresh", apiconf.refreshtoken)
	mux.HandleFunc("POST /api/revoke", apiconf.revoketoken)
	mux.HandleFunc("POST /api/chirps", apiconf.validateChirp)
	mux.HandleFunc("GET /api/chirps", apiconf.getchirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiconf.getchirp)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiconf.deletechirp)
	mux.HandleFunc("POST /api/polka/webhooks", apiconf.upgradeuser)
	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}
	go nicemessage()
	log.Fatal(server.ListenAndServe())
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
	if c.platform != "dev" {
		w.WriteHeader(403)
		return
	}
	w.WriteHeader(200)
	c.db.ResetUsers(req.Context())
	w.Write([]byte("Users table resetted successfully"))
	c.fileserverhits.Store(0)
}

func (c *apiConfig) createUser(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	defer req.Body.Close()
	var user ParseUser
	err := decoder.Decode(&user)
	if err != nil {
		responseunknownerror(w)
		return
	}
	hashedpassw, err := auth.HashPassword(user.Password)
	params := database.CreateUserParams{
		Email:          user.Email,
		HashedPassword: hashedpassw,
	}
	u, err := c.db.CreateUser(req.Context(), params)
	if err != nil {
		responseunknownerror(w)
		return
	}
	w.WriteHeader(201)
	returnvalue := ReturnUser{
		ID:        u.ID,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
		Email:     u.Email,
	}
	data, err := json.Marshal(returnvalue)
	if err != nil {
		responseunknownerror(w)
		return
	}
	responsewithjson(w, data)
	return
}

func (c *apiConfig) validateChirp(w http.ResponseWriter, req *http.Request) {
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
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		responsewitherror(w, 401, "Unauthorized")
		return
	}
	id, err := auth.ValidateJWT(token, c.secret)
	if err != nil {
		responsewitherror(w, 401, "Unauthorized")
		return
	}
	if len(reqbody.Body) > 140 {
		responsewitherror(w, 400, "Chirp is too long")
		return
	} else {
		cleantext := profanitycheck(reqbody.Body)
		params := database.CreateChirpParams{
			Body:   cleantext,
			UserID: id,
		}
		chirp, err := c.db.CreateChirp(req.Context(), params)
		if err != nil {
			responseunknownerror(w)
			return
		}
		resmessage := mapchirp(chirp)
		marshaled, err := json.Marshal(resmessage)
		if err != nil {
			responseunknownerror(w)
		}
		w.WriteHeader(201)
		responsewithjson(w, marshaled)
		return
	}
}

func (c *apiConfig) getchirps(w http.ResponseWriter, req *http.Request) {
	chirps, err := c.db.GetAllChirps(req.Context())
	if err != nil {
		responseunknownerror(w)
		return
	}
	allchirps := []Chirp{}
	for _, v := range chirps {
		allchirps = append(allchirps, mapchirp(v))
	}
	marshaled, err := json.Marshal(allchirps)
	if err != nil {
		responseunknownerror(w)
	}
	w.WriteHeader(200)
	responsewithjson(w, marshaled)
	return
}

func (c *apiConfig) getchirp(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("chirpID")
	uifordb, err := uuid.Parse(id)
	if err != nil {
		responsewitherror(w, 401, "Wrong id")
		return
	}
	dbchirp, err := c.db.GetChirp(req.Context(), uifordb)
	if err != nil {
		responsewitherror(w, 404, "Error not found")
		return
	}
	chirp := mapchirp(dbchirp)
	marshaled, err := json.Marshal(chirp)
	if err != nil {
		responseunknownerror(w)
		return
	}
	w.WriteHeader(200)
	responsewithjson(w, marshaled)
}

func (c *apiConfig) deletechirp(w http.ResponseWriter, req *http.Request) {
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		responsewitherror(w, 401, "Unauthorized")
		return
	}
	userid, err := auth.ValidateJWT(token, c.secret)
	if err != nil {
		responsewitherror(w, 403, "Forbidden")
		return
	}
	id := req.PathValue("chirpID")
	idfordb, err := uuid.Parse(id)
	if err != nil {
		responsewitherror(w, 401, "Unauthorized")
		return
	}
	chirp, err := c.db.GetChirp(req.Context(), idfordb)
	if err != nil {
		responsewitherror(w, 404, "Not found")
	}
	if chirp.UserID != userid {
		responsewitherror(w, 403, "Forbidden")
	}
	params := database.DeleteChirpParams{
		ID:     idfordb,
		UserID: userid,
	}
	if err := c.db.DeleteChirp(req.Context(), params); err != nil {
		responsewitherror(w, 404, "Chirp not found.")
		return
	}
	w.WriteHeader(204)
}

func (c *apiConfig) login(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	defer req.Body.Close()
	var userdata ParseUser
	err := decoder.Decode(&userdata)
	if err != nil {
		responseunknownerror(w)
		return
	}
	dbuser, err := c.db.GetUserByEmail(req.Context(), userdata.Email)
	if err != nil {
		responsewitherror(w, 401, "Incorrect email or password")
		return
	}
	if err := auth.CheckPasswordHash(dbuser.HashedPassword, userdata.Password); err != nil {
		responsewitherror(w, 401, "Incorrect email or password")
		return
	}
	token, err := c.CreateTokenForUser(dbuser.ID)
	if err != nil {
		responseunknownerror(w)
		return
	}
	refreshtoken, err := c.createrefreshtoken(dbuser.ID)
	if err != nil {
		responseunknownerror(w)
		return
	}
	returnvalue := mapuser(dbuser)
	returnvalue.Token = token
	returnvalue.RefreshToken = refreshtoken.Token
	data, err := json.Marshal(returnvalue)
	if err != nil {
		responseunknownerror(w)
		return
	}
	responsewithjson(w, data)
}

func (c *apiConfig) refreshtoken(w http.ResponseWriter, req *http.Request) {
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		responsewitherror(w, 401, "Unauthorized")
		return
	}
	tokendata, err := c.db.GetRefreshByToken(req.Context(), token)
	if err != nil {
		responsewitherror(w, 401, "Unauthorized")
		return
	}
	if tokendata.RevokedAt.Valid == true {
		responsewitherror(w, 401, "Unauthorized")
		return
	}
	user, err := c.db.GetUserByRefreshToken(req.Context(), token)
	if err != nil {
		responsewitherror(w, 405, "error here")
		return
	}
	newtoken, err := c.CreateTokenForUser(user.ID)
	if err != nil {
		responseunknownerror(w)
		return
	}
	var returnstruct struct {
		Token string `json:"token"`
	}
	returnstruct.Token = newtoken
	data, err := json.Marshal(returnstruct)
	if err != nil {
		responseunknownerror(w)
		return
	}
	responsewithjson(w, data)
}

func (c *apiConfig) createrefreshtoken(id uuid.UUID) (database.RefreshToken, error) {
	refreshtoken, _ := auth.MakeRefreshToken()
	params := database.CreateRefreshTokenParams{
		Token:     refreshtoken,
		UserID:    uuid.NullUUID{UUID: id, Valid: true},
		ExpiresAt: time.Now().Add(time.Hour * 1440),
	}
	token, err := c.db.CreateRefreshToken(context.Background(), params)
	return token, err
}

func (c *apiConfig) revoketoken(w http.ResponseWriter, req *http.Request) {
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		responsewitherror(w, 404, "Not found")
		return
	}
	params := database.RevokeTokenParams{
		Token:     token,
		RevokedAt: sql.NullTime{Time: time.Now(), Valid: true},
	}
	err = c.db.RevokeToken(req.Context(), params)
	if err != nil {
		responseunknownerror(w)
		return
	}
	w.WriteHeader(204)
}

func (c *apiConfig) updateuser(w http.ResponseWriter, req *http.Request) {
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		responsewitherror(w, 401, "Unauthorized")
		return
	}
	id, err := auth.ValidateJWT(token, c.secret)
	if err != nil {
		responsewitherror(w, 401, "Unauthorized")
		return
	}
	decoder := json.NewDecoder(req.Body)
	var user ParseUser
	err = decoder.Decode(&user)
	if err != nil {
		responseunknownerror(w)
		return
	}
	hashed, err := auth.HashPassword(user.Password)
	if err != nil {
		responseunknownerror(w)
		return
	}
	params := database.UpdateUserCredentialsParams{
		Email:          user.Email,
		HashedPassword: hashed,
		ID:             id,
	}
	almostreturnuser, err := c.db.UpdateUserCredentials(req.Context(), params)
	if err != nil {
		responseunknownerror(w)
		return
	}
	returnuser := mapuser(almostreturnuser)
	data, err := json.Marshal(returnuser)
	if err != nil {
		responseunknownerror(w)
		return
	}
	responsewithjson(w, data)
}

func (c *apiConfig) upgradeuser(w http.ResponseWriter, req *http.Request) {
	apikey, err := auth.GetAPIKey(req.Header)
	if err != nil {
		responsewitherror(w, 401, "Unauthorized")
		return
	}
	if apikey != c.polkakey {
		responsewitherror(w, 401, "Unauthorized")
		return
	}
	decoder := json.NewDecoder(req.Body)
	defer req.Body.Close()
	var webhook WebHook
	err = decoder.Decode(&webhook)
	if err != nil {
		responseunknownerror(w)
		return
	}
	if webhook.Event != "user.upgraded" {
		w.WriteHeader(204)
		return
	}
	err = c.db.UpgradeUser(req.Context(), webhook.Data.UserID)
	if err != nil {
		responseunknownerror(w)
		return
	}
	w.WriteHeader(204)
}

func mapuser(b database.User) ReturnUser {
	return ReturnUser{
		ID:          b.ID,
		CreatedAt:   b.CreatedAt,
		UpdatedAt:   b.UpdatedAt,
		Email:       b.Email,
		IsChirpyRed: b.IsChirpyRed,
	}
}

func mapchirp(b database.Chirp) Chirp {
	return Chirp{
		ID:        b.ID,
		CreatedAt: b.CreatedAt,
		UpdatedAt: b.UpdatedAt,
		Body:      b.Body,
		UserId:    b.UserID,
	}
}

func (c *apiConfig) CreateTokenForUser(id uuid.UUID) (string, error) {
	return auth.MakeJWT(id, c.secret, time.Duration(4800)*time.Second)
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
