package database

import (
	"auth_service/pkg/service"
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       string `bson:"_id"`
	Username string `bson:"username"`
	Password string `bson:"password"`
}

//func (d *Database) CreateUser(ctx context.Context, user *service.User) error {
//	_, err := d.userCollection.InsertOne(ctx, User{
//		ID:       user.ID,
//		Username: user.Username,
//		Password: user.Password,
//	})
//
//	if err != nil {
//		return fmt.Errorf("cannot insert user: %w", err)
//	}
//
//	return nil
//}
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
func (d *Database) ListUsers(ctx context.Context) ([]service.User, error) {
	cur, err := d.userCollection.Find(ctx, bson.M{})
	if err != nil {
		return nil, fmt.Errorf("cannot find users: %w", err)
	}
	defer cur.Close(ctx)

	res := make([]service.User, 0)
	for cur.Next(ctx) {
		usr := User{}

		err = cur.Decode(&usr)
		if err != nil {
			return nil, fmt.Errorf("cannot decode user: %w", err)
		}

		res = append(res, service.User{
			ID:       usr.ID,
			Username: usr.Username,
			Password: usr.Password,
		})
	}

	return res, nil
}

func (d *Database) FindUser(ctx context.Context, username string, password string) (bool, error) {
	curr, err := d.userCollection.Find(ctx, bson.M{"username": username})
	if err != nil {
		return false, fmt.Errorf("no user: %w", err)
	}
	defer curr.Close(ctx)
	res := make([]service.User, 0)
	for curr.Next(ctx) {
		usr := User{}

		err = curr.Decode(&usr)
		if err != nil {
			return false, fmt.Errorf("cannot decode user: %w", err)
		}

		res = append(res, service.User{
			ID:       usr.ID,
			Username: usr.Username,
			Password: usr.Password,
		})
	}
	isUser := CheckPasswordHash(password, res[0].Password)
	return isUser, nil
}
