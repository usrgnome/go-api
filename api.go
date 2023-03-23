package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/jellydator/ttlcache/v3"
)

type apiFunc func(http.ResponseWriter, *http.Request) error
type protectedApiFunc func(http.ResponseWriter, *http.Request, int) error

func WriteJson(w http.ResponseWriter, status int, v any) error {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

type ApiError struct {
	Error string `json:"error"`
}

func makeHTTPHandleFunc(f apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err != nil {
			// handle error
			WriteJson(w, http.StatusBadRequest, ApiError{Error: err.Error()})
		}
	}
}

type ServerPayload struct {
	Name      string `json:"name"`
	Region    string `json:"region"`
	Subdomain string `json:"subdomain"`
	Port      string `json:"port"`
	Players   int    `json:"players"`
	Ssl       bool   `json:"ssl"`
}

type APIServer struct {
	listenAddr string
	store      Storage
	cache      *ttlcache.Cache[string, ServerPayload]
}

/*

	cache ttlcache.New[string, string]()

	cache.Set("bob", "ross", time.Second*1)

*/

func NewAPIServer(listenAddr string, store Storage) *APIServer {
	apiServer := &APIServer{
		listenAddr: listenAddr,
		store:      store,
		cache: ttlcache.New[string, ServerPayload](
			ttlcache.WithTTL[string, ServerPayload](5 * time.Second),
		),
	}

	go apiServer.cache.Start()

	return apiServer
}

func (s *APIServer) Run() error {
	router := mux.NewRouter()

	router.HandleFunc("/auth/login", makeHTTPHandleFunc(s.handleLogin)).Methods("POST")
	router.HandleFunc("/auth/signup", makeHTTPHandleFunc(s.handleCreateAccount)).Methods("POST")
	router.HandleFunc("/auth/accounts", makeHTTPHandleFunc(s.handleAccounts)).Methods("GET")
	router.HandleFunc("/auth/profile", withJWTAuth(s.handleGetProfile, s.store)).Methods("GET")
	router.HandleFunc("/auth/token", withJWTAuth(s.handleGetToken, s.store)).Methods("GET")
	router.HandleFunc("/auth/refresh", withJWTRefresh(s.store)).Methods("GET")
	router.HandleFunc("/auth/logout", withJWTLogout(s.store)).Methods("GET")
	router.HandleFunc("/getServerToken", s.handleGetServerToken()).Methods("GET")
	router.HandleFunc("/servers", s.handleGetServers).Methods("GET")
	router.HandleFunc("/updateServer", s.handleAddServer).Methods("POST")
	router.HandleFunc("/updateAccount", s.handleUpdateAccount()).Methods("POST")

	log.Println("json web server running on port: ", s.listenAddr)
	return http.ListenAndServe(s.listenAddr, router)
}

func (s *APIServer) handleUpdateAccount() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		fmt.Println("update account called!")

		var req UpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			permissionDenied(w)
			return
		}

		tokenString := r.Header.Get("authorization")

		fmt.Println("got server token: ", tokenString)

		token, err := validateServerJWT(tokenString)

		if err != nil {
			fmt.Println("server token error", err.Error())
			permissionDenied(w)
			return
		}

		if !token.Valid {
			fmt.Println("server token not valid")
			permissionDenied(w)
			return
		}

		if claims, ok := token.Claims.(*ServerJWTClaims); ok && token.Valid {
			id := claims.Id

			err := s.store.UpdateAccount(id, req.Score)

			if err != nil {
				WriteJson(w, http.StatusForbidden, ApiError{Error: err.Error()})
				return
			}

			fmt.Println("got updated acc: ", id, " with add score: ", req.Score)
			w.WriteHeader(http.StatusOK)
			return
		} else {
			fmt.Println(err)
			permissionDenied(w)
			return
		}
	}
}

var serverAPIPass = os.Getenv("API_PASSWORD")

func (s *APIServer) handleAddServer(w http.ResponseWriter, r *http.Request) {

	password := r.Header.Get("authorization")

	if password != serverAPIPass {
		WriteJson(w, http.StatusForbidden, ApiError{Error: "invalid api password!, expected: " + serverAPIPass})
		return
	}

	var req ServerPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Println("ERROR", r.Body)
		return
	}

	s.cache.Set(req.Name, req, ttlcache.DefaultTTL)

	w.WriteHeader(http.StatusOK)
	return
}

func (s *APIServer) handleGetServers(w http.ResponseWriter, r *http.Request) {
	servers := []ServerPayload{}

	items := s.cache.Items()
	for _, t := range items {
		servers = append(servers, t.Value())
	}

	WriteJson(w, http.StatusOK, servers)
}

func (s *APIServer) handleGetServerToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("authorization")

		fmt.Println("got auth token: ", tokenString)

		token, err := validateClientJWT(tokenString)

		if err != nil {
			fmt.Println("client token error", err.Error())
			permissionDenied(w)
			return
		}

		if !token.Valid {
			fmt.Println("client token not valid")
			permissionDenied(w)
			return
		}

		if claims, ok := token.Claims.(*ClientJWTClaims); ok && token.Valid {
			id := claims.Id
			serverToken, err := createServerJWT(id)

			if err != nil {
				WriteJson(w, http.StatusForbidden, ApiError{Error: err.Error()})
				return
			}

			fmt.Println("got server token: ", tokenString)
			WriteJson(w, http.StatusOK, TokenResponse{Token: serverToken})

			return
		} else {
			fmt.Println(err)
			permissionDenied(w)
			return
		}
	}
}

func (s *APIServer) handleAccounts(w http.ResponseWriter, r *http.Request) error {

	accounts, err := s.store.GetAccounts()

	if err != nil {
		return err
	}

	fmt.Println("handleGetProfile", "got account!")
	return WriteJson(w, http.StatusOK, accounts)
}

func (s *APIServer) handleGetToken(w http.ResponseWriter, r *http.Request, accID int) error {

	fmt.Printf("inside token handler", accID)
	fmt.Println("handleGetProfile", "got account!")

	clientToken, err := createClientJWT(accID)

	if err != nil {
		return err
	}

	resp := &TokenResponse{
		Token: clientToken,
	}

	return WriteJson(w, http.StatusOK, resp)
}

func (s *APIServer) handleGetProfile(w http.ResponseWriter, r *http.Request, accID int) error {

	fmt.Printf("inside profiler handler", accID)

	account, err := s.store.GetAccountByID(accID)

	if err != nil {
		return err
	}

	fmt.Println("handleGetProfile", "got account!")
	return WriteJson(w, http.StatusOK, account)
}

func (s *APIServer) handleLogin(w http.ResponseWriter, r *http.Request) error {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return err
	}

	acc, err := s.store.GetAccountByEmail(req.Email)

	if err != nil {
		return err
	}

	if !acc.ValidatePassword(req.Password) {
		return fmt.Errorf("Incorrect password")
	}

	refreshToken, err := createRefreshJWT(acc)

	if err != nil {
		return err
	}

	fmt.Printf("%+v\n", acc)

	// todo, remove this and instead return a access token from the login route as well
	resp := LoginResponse{
		Token: refreshToken,
		Id:    int64(acc.ID),
	}

	expiration := time.Now().Add(365 * 24 * time.Hour)
	cookie := http.Cookie{Name: "refresh_token", Value: refreshToken, Expires: expiration}
	http.SetCookie(w, &cookie)
	return WriteJson(w, http.StatusOK, resp)
}

func (s *APIServer) handleGetAccount(w http.ResponseWriter, r *http.Request) error {
	accounts, err := s.store.GetAccounts()

	if err != nil {
		return err
	}

	return WriteJson(w, http.StatusOK, accounts)
}

func (s *APIServer) handleGetAccountById(w http.ResponseWriter, r *http.Request, store Storage) error {
	id, err := getID(r)
	if err != nil {
		return err
	}

	account, err := s.store.GetAccountByID(id)
	if err != nil {
		return err
	}

	return WriteJson(w, http.StatusOK, account)
}

func (s *APIServer) handleCreateAccount(w http.ResponseWriter, r *http.Request) error {
	req := new(CreateAccountRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		fmt.Println("Error serialising json")
		return err
	}

	account, err := NewAccount(req.Username, req.Email, req.Password)

	fmt.Printf("%+v\n", req)

	if err != nil {
		return err
	}

	if err := s.store.CreateAccount(account); err != nil {
		fmt.Println("Error creating account", err.Error())
		return err
	}

	//tokenString, err := createJWT(account)
	//if err != nil {
	//return err
	//}

	//fmt.Println("jwt token: ", tokenString)

	return WriteJson(w, http.StatusOK, account)
}

func (s *APIServer) handleDeleteAccount(w http.ResponseWriter, r *http.Request) error {
	id, err := getID(r)
	if err != nil {
		return err
	}

	if err := s.store.DeleteAccount(id); err != nil {
		return err
	}

	return WriteJson(w, http.StatusOK, map[string]int{"deleted:": id})
}

func (s *APIServer) handleTransfer(w http.ResponseWriter, r *http.Request, store Storage) error {
	TransferRequest := new(TransferRequest)
	if err := json.NewDecoder(r.Body).Decode(TransferRequest); err != nil {
		return err
	}

	defer r.Body.Close()

	return WriteJson(w, http.StatusOK, TransferRequest)
}

func getID(r *http.Request) (int, error) {
	idStr := mux.Vars(r)["id"]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return id, fmt.Errorf("invalid id given %s", idStr)
	}

	return id, nil
}

// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50TnVtYmVyIjozNjA5LCJleHBpcmVzQXQiOjE1MTYyMzkwMjJ9.Umf2LKeF4A_XZdnuJLo-ySYojRX9q1pKmA2gx5tHrxE

func permissionDenied(w http.ResponseWriter) {
	WriteJson(w, http.StatusForbidden, ApiError{Error: "permission denied: "})
}

func withJWTAuth(handlerFunc protectedApiFunc, s Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("calling JWT auth middleware")

		tokenString := r.Header.Get("authorization")

		fmt.Println("got auth token: ", tokenString)

		token, err := validateAuthJWT(tokenString)

		if err != nil {
			fmt.Println("auth token error", err.Error())
			permissionDenied(w)
			return
		}

		if !token.Valid {
			fmt.Println("auth token not valid")
			permissionDenied(w)
			return
		}

		if claims, ok := token.Claims.(*AuthJWTClaims); ok && token.Valid {
			id := claims.Id
			fmt.Println("got auth token: ", tokenString)
			if err := handlerFunc(w, r, id); err != nil {
				WriteJson(w, http.StatusForbidden, ApiError{Error: err.Error()})
			}
			return
		} else {
			fmt.Println(err)
			permissionDenied(w)
			return
		}
	}
}

func withJWTLogout(s Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("calling JWT refresh auth middleware")

		found := false
		var refresh_token string

		for _, c := range r.Cookies() {
			fmt.Println(c)
			if c.Name == "refresh_token" {
				found = true
				refresh_token = c.Value
				break
			}
		}

		// can unset the cookie
		c := &http.Cookie{
			Name:   "refresh_token",
			MaxAge: -1,
		}

		http.SetCookie(w, c)

		fmt.Println("trying to logout")

		if !found {
			permissionDenied(w)
			return
		}

		token, err := validateRefreshJWT(refresh_token)

		fmt.Println("trying to logoutww 2")
		if err != nil || !token.Valid {
			permissionDenied(w)
			return
		}

		fmt.Println("trying to logout writing header")
		w.WriteHeader(http.StatusOK)
	}
}

func withJWTRefresh(s Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("calling JWT refresh auth middleware")

		found := false
		var refresh_token string

		for _, c := range r.Cookies() {
			fmt.Println(c)
			if c.Name == "refresh_token" {
				found = true
				refresh_token = c.Value
				break
			}
		}

		if !found {
			permissionDenied(w)
			return
		}

		token, err := validateRefreshJWT(refresh_token)

		fmt.Println("Successfully refresh token'd a user")

		if err != nil {
			permissionDenied(w)
			return
		}

		if !token.Valid {
			permissionDenied(w)
			return
		}

		if err != nil {
			permissionDenied(w)
			return
		}

		// generate a access token
		if claims, ok := token.Claims.(*RefreshJWTClaims); ok && token.Valid {
			id := claims.Id
			accessToken, err := createAuthJWT(id)

			if err != nil {
				permissionDenied(w)
				return
			}

			WriteJson(w, http.StatusOK, RefreshResponse{Token: accessToken})
			return
		} else {
			fmt.Println(err)
			permissionDenied(w)
			return
		}

		//claims := token.Claims.(jwt.MapClaims)

		//fmt.Println(account.ID, claims["accountNumber"])
		//if account.ID != int(claims["accountNumber"].(float64)) {
		//permissionDenied(w)
		//return
		//}
	}
}
