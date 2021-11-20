package auth

import (
	"auth_service/pkg/conf"
	"auth_service/pkg/db"
	"auth_service/pkg/models"
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSignInHandler(t *testing.T) {

	config := conf.New()
	log.Println(config)
	userDAO := db.InMemroyUserDAO{}
	users := &db.Users
	password, _ := HashPassword("password")
	db.ConnectMongoDB(context.TODO(), config)
	userDBDAO := db.NewMongoDBTemp(context.TODO(), db.GetMongoDBConnection())
	(*users)["testuser"] = &models.User{
		Username: "testuser",
		Password: password,
	}

	b := new(bytes.Buffer)
	err := json.NewEncoder(b).Encode(models.LoginCredentials{
		Username: "user1",
		Password: "password",
	})

	if err != nil {
		t.Fatal(err)
	}

	wr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/i", b)
	reqlogin := httptest.NewRequest(http.MethodPost, "/login", b)
	body, _ := ioutil.ReadAll(wr.Body)
	defer req.Body.Close()

	SignInHandler(config, &userDAO, context.TODO(), userDBDAO)(wr, reqlogin)
	if wr.Code != http.StatusOK {
		t.Errorf("got HTTP status code %d, expected 200, %v", wr.Code, string(body))
	}

	var flagAccess, flagRefresh bool
	for _, cookie := range wr.Result().Cookies() {
		switch {
		case cookie.Name == "Access" && cookie.Value != "":
			flagAccess = true
		case cookie.Name == "Refresh" && cookie.Value != "":
			flagRefresh = true
		}
	}

	if !flagAccess && flagRefresh {
		t.Error("Not enough token headers")
	}

}
