package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"sync/atomic"
	"time"

	"github.com/ctiller15/chirpy/internal/auth"
	"github.com/ctiller15/chirpy/internal/database"
	"github.com/ctiller15/chirpy/utils"
	"github.com/google/uuid"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	secret         string
	polka_key      string
}

func NewApiConfig(db *database.Queries, platform string, secret string, polka_key string) *apiConfig {
	cfg := apiConfig{
		db:        db,
		platform:  platform,
		secret:    secret,
		polka_key: polka_key,
	}

	return &cfg
}

func (cfg *apiConfig) MiddlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) HandleCreateChirp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	type parameters struct {
		Body string `json:"body"`
	}

	bearerToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 400, err.Error())
		return
	}

	type responseStruct struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserID    uuid.UUID `json:"user_id"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {

		log.Printf("Error decoding parameters: %s", err)

		respondWithError(w, 403, "Something went wrong")
		return
	}

	userID, err := auth.ValidateJWT(bearerToken, cfg.secret)

	if err != nil {
		respondWithError(w, 401, "unauthorized")
		return
		// Then you could log the error in a logging service.
	}

	if len(params.Body) > 140 {
		respondWithError(w, 400, "Chirp is too long")
		return
	} else {
		cleanedText := utils.CleanProfanity(params.Body)
		createChirpParams := database.CreateChirpParams{
			UserID: userID,
			Body:   cleanedText,
		}
		result, err := cfg.db.CreateChirp(ctx, createChirpParams)
		if err != nil {
			respondWithError(w, 403, err.Error())
			return
		}

		response := responseStruct{
			ID:        result.ID,
			Body:      result.Body,
			CreatedAt: result.CreatedAt,
			UpdatedAt: result.UpdatedAt,
			UserID:    result.UserID,
		}

		respondWithJSON(w, 201, response)
	}
}

func (cfg *apiConfig) HandleGetChirps(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	author_id_query := r.URL.Query().Get("author_id")
	var author_id uuid.UUID
	if author_id_query == "" {
		author_id = uuid.Nil
	} else {
		author_id = uuid.MustParse(author_id_query)
	}

	sortDir := r.URL.Query().Get("sort")
	if sortDir == "" {
		sortDir = "asc"
	}

	type responseStruct struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserID    uuid.UUID `json:"user_id"`
	}

	var chirps []database.Chirp

	if author_id == uuid.Nil {
		db_chirps, err := cfg.db.GetChirps(ctx)
		if err != nil {
			respondWithError(w, 500, err.Error())
			return
		}

		chirps = db_chirps
	} else {
		db_chirps, err := cfg.db.GetChirpsByUserID(ctx, author_id)
		if err != nil {
			respondWithError(w, 500, err.Error())
			return
		}
		chirps = db_chirps
	}

	response := make([]responseStruct, 0)
	for _, chirp := range chirps {
		response = append(response, responseStruct(chirp))
	}

	if sortDir == "desc" {
		sort.Slice(response, func(i, j int) bool {
			return response[i].CreatedAt.After(response[j].CreatedAt)
		})
	} else {
		sort.Slice(response, func(i, j int) bool {
			return response[i].CreatedAt.Before(response[j].CreatedAt)
		})
	}

	respondWithJSON(w, 200, response)
}

func (cfg *apiConfig) HandleGetChirpByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	chirpID := uuid.MustParse(r.PathValue("chirpID"))

	type responseStruct struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserID    uuid.UUID `json:"user_id"`
	}

	chirp, err := cfg.db.GetChirpByID(ctx, chirpID)
	if err != nil {
		respondWithError(w, 404, err.Error())
		return
	}

	respondWithJSON(w, 200, responseStruct(chirp))
}

func (cfg *apiConfig) HandleDeleteChirpByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	chirpID := uuid.MustParse(r.PathValue("chirpID"))

	accessToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, err.Error())
		return
	}

	userID, err := auth.ValidateJWT(accessToken, cfg.secret)
	if err != nil {
		respondWithError(w, 401, err.Error())
		return
	}

	chirp, err := cfg.db.GetChirpByID(ctx, chirpID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondWithError(w, 404, "chirp not found")
			return
		}
		respondWithError(w, 500, err.Error())
		return
	}

	if userID != chirp.UserID {
		w.WriteHeader(403)
		return
	}

	err = cfg.db.DeleteChirpByID(ctx, chirp.ID)
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	w.WriteHeader(204)
}

func (cfg *apiConfig) HandleLoginUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	type responseStruct struct {
		ID           uuid.UUID `json:"id"`
		CreatedAt    time.Time `json:"created_at"`
		UpdatedAt    time.Time `json:"updated_at"`
		Email        string    `json:"email"`
		Token        string    `json:"token"`
		RefreshToken string    `json:"refresh_token"`
		IsChirpyRed  bool      `json:"is_chirpy_red"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)

	if err != nil {
		log.Printf("error decoding parameters: %s", err)

		respondWithError(w, 500, "Something went wrong")
		return
	}

	user, err := cfg.db.GetUserByEmail(ctx, params.Email)
	if err != nil {
		respondWithError(w, 401, "incorrect email or password")
		return
	}

	err = auth.CheckPasswordHash(params.Password, user.HashedPassword.String)
	if err != nil {
		respondWithError(w, 401, "incorrect email or password")
		return
	}

	newJWT, err := auth.MakeJWT(user.ID, cfg.secret)
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	newRefreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	createRefreshTokenParams := database.CreateRefreshTokenParams{
		Token:  newRefreshToken,
		UserID: user.ID,
	}
	refreshToken, err := cfg.db.CreateRefreshToken(ctx, createRefreshTokenParams)
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	respondWithJSON(w, 200, responseStruct{
		ID:           user.ID,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
		Email:        user.Email,
		Token:        newJWT,
		RefreshToken: refreshToken.Token,
		IsChirpyRed:  user.IsChirpyRed,
	})
}

func (cfg *apiConfig) HandleUpdateUser(w http.ResponseWriter, r *http.Request) {
	accessToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, err.Error())
		return
	}

	ctx := r.Context()
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	type responseStruct struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Email     string    `json:"email"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)

	if err != nil {
		log.Printf("error decoding parameters: %s", err)

		respondWithError(w, 500, "Something went wrong")
		return
	}

	userID, err := auth.ValidateJWT(accessToken, cfg.secret)
	if err != nil {
		respondWithError(w, 401, err.Error())
		return
	}

	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		respondWithError(w, 401, err.Error())
		return
	}
	updatePasswordParams := database.UpdateUserPasswordParams{
		HashedPassword: sql.NullString{
			String: hashedPassword,
			Valid:  true,
		},
		Email: params.Email,
		ID:    userID,
	}
	err = cfg.db.UpdateUserPassword(ctx, updatePasswordParams)
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	response := responseStruct{
		ID:    userID,
		Email: params.Email,
	}

	respondWithJSON(w, 200, response)
}

func (cfg *apiConfig) HandlePolkaWebhook(w http.ResponseWriter, r *http.Request) {
	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil || apiKey != cfg.polka_key {
		respondWithError(w, 401, "invalid api key")
		return
	}

	ctx := r.Context()
	type parameters struct {
		Event string `json:"event"`
		Data  struct {
			UserID uuid.UUID `json:"user_id"`
		} `json:"data"`
	}

	// This pattern happens a lot. Handle on a refactor.
	params := parameters{}
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&params)

	if err != nil {
		log.Printf("error decoding parameters: %s", err)

		respondWithError(w, 500, "Something went wrong")
		return
	}

	if params.Event != "user.upgraded" {
		w.WriteHeader(204)
		return
	}

	updateChirpyRedStatusParams := database.UpdateChirpyRedStatusParams{
		IsChirpyRed: true,
		ID:          params.Data.UserID,
	}

	_, err = cfg.db.UpdateChirpyRedStatus(ctx, updateChirpyRedStatusParams)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			w.WriteHeader(404)
			return
		}
		respondWithError(w, 500, err.Error())
		return
	}

	w.WriteHeader(204)
}

func (cfg *apiConfig) HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	type responseStruct struct {
		ID          uuid.UUID `json:"id"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
		Email       string    `json:"email"`
		IsChirpyRed bool      `json:"is_chirpy_red"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("error decoding parameters: %s", err)

		respondWithError(w, 500, "Something went wrong")
		return
	}

	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	createUserParams := database.CreateUserParams{
		Email: params.Email,
		HashedPassword: sql.NullString{
			String: hashedPassword,
			Valid:  true,
		},
	}
	user, err := cfg.db.CreateUser(r.Context(), createUserParams)
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	res := responseStruct{
		ID:          user.ID,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
	}

	respondWithJSON(w, 201, res)
}

func (cfg *apiConfig) HandleTokenRefresh(w http.ResponseWriter, r *http.Request) {
	type responseStruct struct {
		Token string `json:"token"`
	}
	ctx := r.Context()
	refresh_token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, err.Error())
		return
	}

	token, err := cfg.db.GetRefreshTokenByToken(ctx, refresh_token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondWithError(w, 401, "invalid refresh token")
			return
		}
		respondWithError(w, 500, err.Error())
		return
	}

	newJWT, err := auth.MakeJWT(token.UserID, cfg.secret)
	if err != nil {
		respondWithError(w, 401, err.Error())
		return
	}

	res := responseStruct{
		Token: newJWT,
	}

	respondWithJSON(w, 200, res)
}

func (cfg *apiConfig) HandleTokenRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	refresh_token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, err.Error())
		return
	}

	err = cfg.db.RevokeRefreshToken(ctx, refresh_token)
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	w.WriteHeader(204)
}

func (cfg *apiConfig) HandleAdminMetrics(w http.ResponseWriter, r *http.Request) {
	const htmlTemplate = `<html>
	<body>
	  <h1>Welcome, Chirpy Admin</h1>
	  <p>Chirpy has been visited %d times!</p>
	</body>
  </html>`
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)

	w.Write([]byte(fmt.Sprintf(htmlTemplate, cfg.fileserverHits.Load())))
}

func (cfg *apiConfig) HandleReset(w http.ResponseWriter, req *http.Request) {
	if cfg.platform != "dev" {
		respondWithError(w, 403, "forbidden")
		return
	}
	ctx := req.Context()
	cfg.fileserverHits.Store(0)

	cfg.db.DeleteUsers(ctx)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}
