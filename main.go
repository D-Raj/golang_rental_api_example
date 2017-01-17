package main

import (
	// standard library
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
	// external dependencies
	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// DATABASE
var db *sql.DB
var err error

// Rental model for exporting to json
type Rental struct {
	ID      string `json:"id, omitempty"`
	City    string `json:"city, omitempty"`
	Address string `json:"address, omitempty"`
	Rent    int    `json:"rent, omitempty"`
	Beds    int    `json:"beds, omitempty"`
	Baths   int    `json:"baths, omitempty"`
	Sqft    int    `json:"square_feet, omitempty"`
}

// Rentals container model for exporting to json.
type Rentals []Rental

// User model for db & oAuth parsing
type User struct {
	ID    string
	Name  string
	Email string
}

// Key model for JWT authorization
type Key int

// MyKey const used for JWT functions
const MyKey Key = 0

// Claims  model for JWT authorization
type Claims struct {
	ID    string `json:"user_id"`
	Name  string `json:"username"`
	Email string `json:"email"`
	// recommended having
	jwt.StandardClaims
}

// HOMEPAGE
const htmlIndex = `<html><body>
<a href="/login">Log in with Google</a>
</body></html>`

var currentUser User

func main() {
	// INITIALIZE DB
	// This is an example login for a mysql db
	db, err = sql.Open("mysql", "root:pass@/rentals")
	if err != nil {
		panic(err.Error())
	}
	defer db.Close()
	err = db.Ping()
	if err != nil {
		panic(err.Error())
	}
	// ROUTES
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/", Index)
	router.HandleFunc("/rentals", ValidateToken(RentalIndex)).Methods("GET")
	router.HandleFunc("/rentals", ValidateToken(RentalNew)).Methods("POST")
	router.HandleFunc("/rentals/{rentalID}", ValidateToken(RentalShow)).Methods("GET")
	router.HandleFunc("/rentals/{rentalID}", ValidateToken(RentalDestroy)).Methods("DELETE")
	router.HandleFunc("/login", Login)
	router.HandleFunc("/logout", Logout)
	router.HandleFunc("/authcallback", AuthCallback)
	router.HandleFunc("/settoken", SetToken)
	log.Fatal(http.ListenAndServe(":8080", router))
}

// API

// Index is the homepage of the api
func Index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, htmlIndex)
}

// RentalIndex shows all rentals associated w/ a user
func RentalIndex(w http.ResponseWriter, r *http.Request) {
	// protect page with JWT
	claims, ok := r.Context().Value(MyKey).(Claims)
	if !ok {
		http.Redirect(w, r, "/", 307)
		return
	}
	fmt.Fprintf(w, "Hello %s", claims.Name)

	rentals := Rentals{}
	rows, err := db.Query("SELECT * FROM rentals WHERE user_id = ?;", claims.ID)
	if err != nil {
		fmt.Print(err.Error())
	}
	for rows.Next() {
		rental := Rental{}
		var unused string
		err = rows.Scan(&rental.ID, &rental.City, &rental.Address, &rental.Rent, &rental.Beds, &rental.Baths, &rental.Sqft, &unused)
		rentals = append(rentals, rental)
		if err != nil {
			fmt.Print(err.Error())
		}
	}
	defer rows.Close()
	json.NewEncoder(w).Encode(rentals)
}

// RentalShow responds with a single rental, accessed by ID
func RentalShow(w http.ResponseWriter, r *http.Request) {
	rental := Rental{}
	params := mux.Vars(r)
	rentalID := params["rentalID"]
	err := db.QueryRow("SELECT id, city, address, rent, beds, baths, sqft FROM rentals WHERE id = ?;", rentalID).Scan(&rental.ID, &rental.City, &rental.Address, &rental.Rent, &rental.Beds, &rental.Baths, &rental.Sqft)
	if err != nil {
		fmt.Print(err.Error())
	}
	json.NewEncoder(w).Encode(rental)
}

// RentalNew stores a new rental in the DB
func RentalNew(w http.ResponseWriter, r *http.Request) {
	// GET VALUES FROM POST REQUEST
	city := r.FormValue("city")
	address := r.FormValue("address")
	rent := r.FormValue("rent")
	beds := r.FormValue("beds")
	baths := r.FormValue("baths")
	sqft := r.FormValue("sqft")
	// PREPARE SQL STATEMENT
	stmt, err := db.Prepare("INSERT INTO rentals (city, address, rent, beds, baths, sqft) VALUES (?, ?, ?, ?, ?, ?);")
	if err != nil {
		fmt.Print(err.Error())
	}
	// EXECUTE STATEMENT USING GATHERED VALUES
	_, err = stmt.Exec(city, address, rent, beds, baths, sqft)
	if err != nil {
		fmt.Print(err.Error())
	}
	fmt.Fprintln(w, "Post succesful!")
}

// RentalDestroy removes a rental from DB via ID
func RentalDestroy(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	rentalID := params["rentalID"]
	stmt, err := db.Prepare("DELETE FROM rentals WHERE id= ?;")
	if err != nil {
		fmt.Print(err.Error())
	}
	_, err = stmt.Exec(rentalID)
	if err != nil {
		fmt.Print(err.Error())
	}
	fmt.Fprintln(w, "Deleted succesfully!")
}

// GOOGLE LOGIN W/ OAUTH

var (
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8080/authcallback",
		ClientID:     "837356299785-d6h7rniad39obu7518h1eskeq3uo2htl.apps.googleusercontent.com", // all this should be protected in a production API
		ClientSecret: "X8acf-ED8VKEacw3GgHo4BBi",                                                
		Scopes: []string{"https://www.googleapis.com/auth/userinfo.profile",
			"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint: google.Endpoint,
	}

	oauthStateString = "SecretSauce"
)

// Login allows the user to log in using Google oAuth
func Login(w http.ResponseWriter, r *http.Request) {
	url := googleOauthConfig.AuthCodeURL(oauthStateString)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// AuthCallback is where Google sends the user after they log in
func AuthCallback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	if state != oauthStateString {
		fmt.Printf("invalid oauth state, expected '%s', got '%s'\n", oauthStateString, state)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	code := r.FormValue("code")
	token, err := googleOauthConfig.Exchange(oauth2.NoContext, code)
	if err != nil {
		fmt.Printf("Code exchange failed with '%s'\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		fmt.Println("error:", err)
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println("error:", err)
	}
	NewLogin(contents)
	// check if currentUser has been set
	if currentUser.Name != "" {
		http.Redirect(w, r, "/settoken", 307)
	}
}

// Utility Functions

// NewLogin creates a new user after they have authenticated with google
func NewLogin(userdata []byte) {
	user := User{}
	err = json.Unmarshal(userdata, &user)
	if err != nil {
		fmt.Println("error:", err)
	}
	// check if user exists in db before creating new user
	var userExists string
	err := db.QueryRow("SELECT email FROM users WHERE email = ?;", user.Email).Scan(&userExists)
	if err != nil {
		fmt.Println("error:", err)
	}
	// if user exists, log the user in, and return to index
	if userExists != "" {
		fmt.Println("user already exists")
		currentUser = user
		return
	}
	// create new user if user does not exist, log them in, then return to index
	stmt, err := db.Prepare("INSERT INTO users (name, email) VALUES (?, ?);")
	if err != nil {
		fmt.Print(err.Error())
	}
	_, err = stmt.Exec(user.Name, user.Email)
	if err != nil {
		fmt.Print(err.Error())
	}
	currentUser = user
}

// JWT Implementation

// SetToken creates a new JWT and gives it to an authenticated user
func SetToken(w http.ResponseWriter, r *http.Request) {
	if currentUser.Name == "" {
		http.Redirect(w, r, "/", 307)
		fmt.Print("You must login first")
	}
	expireToken := time.Now().Add(time.Hour * 1).Unix()
	expireCookie := time.Now().Add(time.Hour * 1)
	//get db id for current user

	// get Claims
	claims := Claims{
		currentUser.ID,
		currentUser.Name,
		currentUser.Email,
		jwt.StandardClaims{
			ExpiresAt: expireToken,
			Issuer:    "localhost:8080",
		},
	}
	// create token & sign token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, _ := token.SignedString([]byte("SecretSquirell"))
	// create cookie & set token inside cookie
	cookie := http.Cookie{Name: "Auth", Value: signedToken, Expires: expireCookie, HttpOnly: true}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/rentals", 307)
}

// ValidateToken verifies presence fo JWT
func ValidateToken(page http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 404 if cookie not found
		cookie, err := r.Cookie("Auth")
		if err != nil {
			http.NotFound(w, r)
			return
		}

		// get token from cookie
		token, err := jwt.ParseWithClaims(cookie.Value, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			// verify token has not been modified
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method")
			}
			return []byte("SecretSquirell"), nil
		})
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if claims, ok := token.Claims.(*Claims); ok && token.Valid {
			ctx := context.WithValue(r.Context(), MyKey, *claims)
			page(w, r.WithContext(ctx))
		} else {
			http.NotFound(w, r)
			return
		}
	})
}

// Logout deletes the jwt
func Logout(w http.ResponseWriter, r *http.Request) {
	deleteCookie := http.Cookie{Name: "Auth", Value: "none", Expires: time.Now()}
	http.SetCookie(w, &deleteCookie)
	http.Redirect(w, r, "/", 307)
	return
}
