package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
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

type APIServer struct {
	listenAddr string
	store      Storage
}

func NewAPIServer(listenAddr string, store Storage) *APIServer {
	return &APIServer{
		listenAddr: listenAddr,
		store:      store,
	}
}

func (s *APIServer) Run() error {
	router := mux.NewRouter()

	router.HandleFunc("/auth/login", makeHTTPHandleFunc(s.handleLogin)).Methods("POST")
	router.HandleFunc("/auth/signup", makeHTTPHandleFunc(s.handleCreateAccount)).Methods("POST")
	router.HandleFunc("/auth/account", makeHTTPHandleFunc(s.handleAccount))
	//router.HandleFunc("/auth/accounts", makeHTTPHandleFunc(s.handleAccount, s.store))
	router.HandleFunc("/auth/profile", withJWTAuth(s.handleGetProfile, s.store)).Methods("GET")
	//router.HandleFunc("/auth/account/{id}", makeHTTPHandleFunc(s.handleDeleteAccount, s.store)).Methods("DELETE")
	//router.HandleFunc("/auth/transfer", makeHTTPHandleFunc(s.handleTransfer, s.store)).Methods("POST")
	router.HandleFunc("/auth/refresh", withJWTRefresh(s.store)).Methods("GET")
	router.HandleFunc("/auth/logout", withJWTLogout(s.store)).Methods("GET")

	log.Println("json web server running on port: ", s.listenAddr)

	return http.ListenAndServe(s.listenAddr, router)
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

func (s *APIServer) handleRefresh(w http.ResponseWriter, r *http.Request) error {
	var resp = new(RefreshResponse)
	resp.Token = "Hello world"
	return WriteJson(w, http.StatusOK, resp)
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

// 7861
func (s *APIServer) handleAccount(w http.ResponseWriter, r *http.Request) error {
	if r.Method == "GET" {
		return s.handleGetAccount(w, r)
	} else if r.Method == "POST" {
		return s.handleCreateAccount(w, r)
	} else if r.Method == "DELETE" {
		s.handleDeleteAccount(w, r)
	}
	return fmt.Errorf("method not allowed %s", r.Method)
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
			handlerFunc(w, r, id)
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
