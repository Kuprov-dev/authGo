package errors

import (
	"encoding/json"
	"net/http"
)

func MakeInternalServerErrorResponse(w *http.ResponseWriter, errMsg string) {
	if errMsg == "" {
		errMsg = "Internal server error."
	}
	(*w).Header().Set("Content-Type", "application/json")
	(*w).WriteHeader(http.StatusInternalServerError)
	json.NewEncoder(*w).Encode(ErrorMsg{Message: errMsg})
}

func MakeBadGatewayErrorResponse(w *http.ResponseWriter, errMsg string) {
	if errMsg == "" {
		errMsg = "Bad gateway."
	}
	(*w).Header().Set("Content-Type", "application/json")
	(*w).WriteHeader(http.StatusBadGateway)
	json.NewEncoder(*w).Encode(ErrorMsg{Message: errMsg})
}

func MakeServiceUnavailableErrorResponse(w *http.ResponseWriter, errMsg string) {
	if errMsg == "" {
		errMsg = "External service is unavailable."
	}
	(*w).Header().Set("Content-Type", "application/json")
	(*w).WriteHeader(http.StatusServiceUnavailable)
	json.NewEncoder(*w).Encode(ErrorMsg{Message: errMsg})
}

func MakeBadRequestErrorResponse(w *http.ResponseWriter, errMsg string) {
	if errMsg == "" {
		errMsg = "Something goes wrong."
	}
	(*w).Header().Set("Content-Type", "application/json")
	(*w).WriteHeader(http.StatusBadRequest)
	json.NewEncoder(*w).Encode(ErrorMsg{Message: errMsg})
}

func MakeUnathorisedErrorResponse(w *http.ResponseWriter, errMsg string) {
	if errMsg == "" {
		errMsg = "Unathorised error."
	}
	(*w).Header().Set("Content-Type", "application/json")
	(*w).WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(*w).Encode(ErrorMsg{Message: errMsg})
}

func MakeForbiddenErrorResponse(w *http.ResponseWriter, errMsg string) {
	if errMsg == "" {
		errMsg = "Forbidden error."
	}
	(*w).Header().Set("Content-Type", "application/json")
	(*w).WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(*w).Encode(ErrorMsg{Message: errMsg})
}

func MakeNotFoundErrorResponse(w *http.ResponseWriter, errMsg string) {
	if errMsg == "" {
		errMsg = "Forbidden error."
	}
	(*w).Header().Set("Content-Type", "application/json")
	(*w).WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(*w).Encode(ErrorMsg{Message: errMsg})
}
