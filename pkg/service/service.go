package service

type Service struct {
	userStorage UserStorage
}

func NewService(userStorage UserStorage) *Service {
	return &Service{userStorage: userStorage}
}
