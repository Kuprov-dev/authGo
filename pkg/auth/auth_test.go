package auth

import (
	"auth_service/pkg/conf"
	"auth_service/pkg/db"
	"auth_service/pkg/models"
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSignInHandler(t *testing.T) {
	config := conf.New()
	userDAO := db.InMemroyUserDAO{}
	users := &db.Users
	password, _ := HashPassword("password")

	(*users)["testuser"] = &models.User{
		Username: "testuser",
		Password: password,
	}

	b := new(bytes.Buffer)
	err := json.NewEncoder(b).Encode(models.LoginCredentials{
		Username: "testuser",
		Password: "password",
	})

	if err != nil {
		t.Fatal(err)
	}

	wr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/i", b)

	body, _ := ioutil.ReadAll(wr.Body)
	defer req.Body.Close()

	SignInHandler(config, &userDAO)(wr, req)
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
