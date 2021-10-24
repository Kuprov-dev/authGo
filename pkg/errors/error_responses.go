package errors

import (
	"encoding/json"
	"net/http"
)

func MakeInternalServerErrorResponse(w *http.ResponseWriter) {
	(*w).Header().Set("Content-Type", "application/json")
	(*w).WriteHeader(http.StatusInternalServerError)
	json.NewEncoder(*w).Encode(ErrorMsg{Message: "Internal server error."})
}

func MakeBadGatewayErrorResponse(w *http.ResponseWriter) {
	(*w).Header().Set("Content-Type", "application/json")
	(*w).WriteHeader(http.StatusBadGateway)
	json.NewEncoder(*w).Encode(ErrorMsg{Message: "Bad gateway."})
}

func MakeServiceUnavailableErrorResponse(w *http.ResponseWriter) {
	(*w).Header().Set("Content-Type", "application/json")
	(*w).WriteHeader(http.StatusServiceUnavailable)
	json.NewEncoder(*w).Encode(ErrorMsg{Message: "External service is unavailable."})
}

func MakeBadRequestErrorResponse(w *http.ResponseWriter, errMsg string) {
	(*w).Header().Set("Content-Type", "application/json")
	(*w).WriteHeader(http.StatusBadRequest)
	json.NewEncoder(*w).Encode(ErrorMsg{Message: errMsg})
}

func MakeUnathorisedErrorResponse(w *http.ResponseWriter) {
	(*w).Header().Set("Content-Type", "application/json")
	(*w).WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(*w).Encode(ErrorMsg{Message: "Unathorised error."})
}

func MakeForbiddenErrorResponse(w *http.ResponseWriter) {
	(*w).Header().Set("Content-Type", "application/json")
	(*w).WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(*w).Encode(ErrorMsg{Message: "Forbidden error."})
}

func MakeNotFoundErrorResponse(w *http.ResponseWriter) {
	(*w).Header().Set("Content-Type", "application/json")
	(*w).WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(*w).Encode(ErrorMsg{Message: "Not found."})
}
