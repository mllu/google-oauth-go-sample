package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/mllu/google-oauth-go-sample/database"
	"github.com/mllu/google-oauth-go-sample/structs"

	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var cred Credentials
var conf *oauth2.Config

// Credentials which stores google ids.
type Credentials struct {
	Cid     string `json:"cid"`
	Csecret string `json:"csecret"`
}

// RandToken generates a random @l length token.
func RandToken(l int) string {
	b := make([]byte, l)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func getLoginURL(state string) string {
	return conf.AuthCodeURL(state)
}

func init() {
	file, err := ioutil.ReadFile("./creds.json")
	if err != nil {
		log.Printf("File error: %v\n", err)
		os.Exit(1)
	}
	json.Unmarshal(file, &cred)

	conf = &oauth2.Config{
		ClientID:     cred.Cid,
		ClientSecret: cred.Csecret,
		RedirectURL:  "http://127.0.0.1:9090/callback",
		Scopes: []string{
			// You have to select your own scope from here
			//-> https://developers.google.com/identity/protocols/googlescopes#google_sign-in
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/cloud-platform",
		},
		Endpoint: google.Endpoint,
	}
}

// IndexHandler handels /.
func IndexHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "index.tmpl", gin.H{})
}

// AuthHandler handles authentication of a user and initiates a session.
func AuthHandler(c *gin.Context) {
	// Handle the exchange code to initiate a transport.
	session := sessions.Default(c)
	retrievedState := session.Get("state")
	// debug: print the RawQuery passed from login page
	log.Println("RawQuery:", c.Request.URL.RawQuery)
	queryState := c.Request.URL.Query().Get("state")
	if retrievedState != queryState {
		log.Printf("Invalid session state: retrieved: %s; Param: %s", retrievedState, queryState)
		c.HTML(http.StatusUnauthorized, "error.tmpl", gin.H{"message": "Invalid session state."})
		return
	}
	code := c.Request.URL.Query().Get("code")
	tok, err := conf.Exchange(oauth2.NoContext, code)
	if err != nil {
		log.Println(err)
		c.HTML(http.StatusBadRequest, "error.tmpl", gin.H{"message": "Login failed. Please try again."})
		return
	}

	// save the token
	session.Set("AccessToken", tok.AccessToken)
	session.Set("RefreshToken", tok.RefreshToken)
	session.Set("TokenType", tok.TokenType)
	session.Set("Expiry", tok.Expiry.Format(time.RFC3339))
	session.Save()

	client := conf.Client(oauth2.NoContext, tok)
	userinfo, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		log.Println(err)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	defer userinfo.Body.Close()
	data, _ := ioutil.ReadAll(userinfo.Body)
	// debug: print the response body
	log.Printf("data:\n %s", string(data))
	u := structs.User{}
	if err = json.Unmarshal(data, &u); err != nil {
		log.Println(err)
		c.HTML(http.StatusBadRequest, "error.tmpl", gin.H{"message": "Error marshalling response. Please try agian."})
		return
	}
	session.Set("user-id", u.Email)
	err = session.Save()
	if err != nil {
		log.Println(err)
		c.HTML(http.StatusBadRequest, "error.tmpl", gin.H{"message": "Error while saving session. Please try again."})
		return
	}
	seen := false
	db := database.MongoDBConnection{}
	if _, mongoErr := db.LoadUser(u.Email); mongoErr == nil {
		seen = true
	} else {
		err = db.SaveUser(&u)
		if err != nil {
			log.Println(err)
			c.HTML(http.StatusBadRequest, "error.tmpl", gin.H{"message": "Error while saving user. Please try again."})
			return
		}
	}
	c.HTML(http.StatusOK, "battle.tmpl", gin.H{"email": u.Email, "seen": seen})
}

// LoginHandler handles the login procedure.
func LoginHandler(c *gin.Context) {
	state := RandToken(32)
	session := sessions.Default(c)
	session.Set("state", state)
	session.Save()
	link := getLoginURL(state)
	// debug: print the link
	log.Println("link:", link)
	c.HTML(http.StatusOK, "auth.tmpl", gin.H{"link": link})
}

// FieldHandler is a rudementary handler for logged in users.
func FieldHandler(c *gin.Context) {
	session := sessions.Default(c)
	userID := session.Get("user-id")
	c.HTML(http.StatusOK, "field.tmpl", gin.H{"user": userID})
}

// ListStuff is a handler for listing stuff.
func ListBucket(c *gin.Context) {
	ctx := context.Background()
	session := sessions.Default(c)
	token := new(oauth2.Token)
	token.AccessToken = session.Get("AccessToken").(string)
	token.RefreshToken = session.Get("RefreshToken").(string)
	token.RefreshToken = session.Get("RefreshToken").(string)
	t := session.Get("Expiry").(string)
	token.Expiry, _ = time.Parse(time.RFC3339, t)
	token.TokenType = session.Get("TokenType").(string)
	client := conf.Client(ctx, token)
	bucket, err := client.Get("https://www.googleapis.com/storage/v1/b/oauth2-go-sample")
	if err != nil {
		log.Println(err)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	defer bucket.Body.Close()
	data, _ := ioutil.ReadAll(bucket.Body)
	// debug: print the response body
	log.Printf("data:\n %s", string(data))
	c.String(http.StatusOK, fmt.Sprintf("%s", data))
}
