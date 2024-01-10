package utils

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/remiges-tech/alya/wscutils"
	"github.com/remiges-tech/idshield/types"
	"github.com/remiges-tech/logharbour/logharbour"
)

const (
	ErrTokenMissing            = "token_missing"
	ErrTokenVerificationFailed = "token_verification_failed"
	ErrUnauthorized            = "Unauthorized"
	ErrExist                   = "exist"
	ErrNotExist                = "not_exist"
	ErrWhileGettingInfo        = "Error_while_getting_info"

	ErrInvalidJSON   = "invalid_json"
	ErrAlreadyExist  = "User_already_exists"
	ErrSameEMail     = "User_already_exists_with_same_email"
	ErrRealmNotFound = "Realm_not_found"
	ErrUnknown       = "unknown"

	ErrHTTPUnauthorized      = "401 Unauthorized: HTTP 401 Unauthorized"
	ErrHTTPUserAlreadyExist  = "409 Conflict: User exists with same username"
	ErrHTTPRealmNotFound     = "404 Not Found: Realm not found."
	ErrHTTPUserNotFound      = "404 Not Found: User not found"
	ErrHTTPSameEmail         = "409 Conflict: User exists with same email"
	ErrHTTPGroupNotFound     = "400 Bad Request: Group name is missing"
	ErrHTTPUserNotFoundInReq = "400 Bad Request: User name is missing"

	ErrFailedToLoadDependence = "Failed_to_load_dependence"
	ErrIDandUserNameMissing   = "id_and_username_both_are_missing"
	ERRTokenExpired           = "token_expired"
	ErrUserNotFound           = "user_not_found"
	ErrUserNotAuthorized      = "user_not_authorized_to_perform_this_action"
	ErrInvalidParam           = "invalid_param"
	ErrEitherIDOrUsernameIsSetButNotBoth = "either_ID_or_Username_is_set_but_not_both"
)

// ExtractClaimFromJwt: this will extract the provided singleClaimName as key from the jwt token and return its value as a string
func ExtractClaimFromJwt(tokenString string, singleClaimName string) (string, error) {
	var name string
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("invalid token payload")
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		name = fmt.Sprint(claims[singleClaimName])
	}

	if name == "" {
		return "", fmt.Errorf("invalid token payload")
	}

	return name, nil
}

func Authz_check(op types.OpReq, trace bool) (bool, []string) {
	var caplist []string
	return true, caplist
}

// UnixMilliToTimestamp: will return the unixmilli time (int64) to time.Time using time package
func UnixMilliToTimestamp(unix int64) time.Time {
	tm := time.UnixMilli(unix)
	return tm
}

// GocloakErrorHandler sends a specific error message as a response based on the input error.
func GocloakErrorHandler(c *gin.Context, l *logharbour.Logger, err error) {
	switch true {
	case strings.Contains(err.Error(), ErrHTTPUnauthorized):
		l.LogDebug("Unauthorized error occurred: ", logharbour.DebugInfo{Variables: map[string]interface{}{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(ErrUnauthorized))
	case strings.Contains(err.Error(), ErrHTTPUserAlreadyExist):
		l.Debug0().LogDebug("User already exists error: ", logharbour.DebugInfo{Variables: map[string]interface{}{"error": err}})
		str := "username"
		wscutils.SendErrorResponse(c, wscutils.NewResponse("error", nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(ErrExist, &str)}))
	case strings.Contains(err.Error(), ErrHTTPRealmNotFound):
		l.Debug0().LogDebug("Realm not found error: ", logharbour.DebugInfo{Variables: map[string]interface{}{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(ErrRealmNotFound))
	case strings.Contains(err.Error(), ErrHTTPSameEmail):
		l.Debug0().LogDebug("User exists with same email: ", logharbour.DebugInfo{Variables: map[string]interface{}{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(ErrSameEMail))
	case strings.Contains(err.Error(), ErrHTTPUserNotFound):
		l.Debug0().LogDebug("ID not found: ", logharbour.DebugInfo{Variables: map[string]interface{}{"error": err}})
		str := "ID"
		wscutils.SendErrorResponse(c, wscutils.NewResponse("error", nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(ErrNotExist, &str)}))
	case strings.Contains(err.Error(), ErrHTTPGroupNotFound):
		l.Debug0().LogDebug("Group not found: ", logharbour.DebugInfo{Variables: map[string]interface{}{"error": err}})
		str := "Name"
		wscutils.SendErrorResponse(c, wscutils.NewResponse("error", nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(ErrNotExist, &str)}))
	case strings.Contains(err.Error(), ErrHTTPUserNotFoundInReq):
		l.Debug0().LogDebug("user name not found: ", logharbour.DebugInfo{Variables: map[string]interface{}{"error": err}})
		str := "username"
		wscutils.SendErrorResponse(c, wscutils.NewResponse("error", nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(ErrNotExist, &str)}))
	default:
		l.Debug0().LogDebug("Unknown error occurred: ", logharbour.DebugInfo{Variables: map[string]interface{}{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(wscutils.ErrcodeUnknown))
	}

}

func GetRealmFromJwt(c *gin.Context, token string) string {
	realm, err := ExtractClaimFromJwt(token, "iss")
	if err != nil {
		return ""
	}
	split := strings.Split(realm, "/")
	realm = split[len(split)-1]
	return realm
}

// qualifiedCapToString converts a types.QualifiedCap to a JSON-formatted string.
// It concatenates the cap, scope, and limit fields into a single string.
func qualifiedCapToString(qc types.QualifiedCap) (string, error) {
	// Convert Scope and Limit to JSON strings
	scopeJSON, err := json.Marshal(qc.Scope)
	if err != nil {
		return "", err
	}
	limitJSON, err := json.Marshal(qc.Limit)
	if err != nil {
		return "", err
	}
	id := uuid.New().String()
	// Concatenate fields into a single string
	result := fmt.Sprintf("{\"id\": \"%s\", \"cap\": \"%s\", \"scope\": %s, \"limit\": %s}", id, qc.Cap, string(scopeJSON), string(limitJSON))
	// result := fmt.Sprintf("{\"cap\": \"%s\", \"scope\": %s, \"limit\": %s}", qc.Cap, string(scopeJSON), string(limitJSON))
	return result, nil
}

// CapabilitiesToString converts a types.Capabilities to a JSON-formatted string.
// It includes the name and a slice of QualifiedCaps converted to strings.
func CapabilitiesToString(caps types.Capabilities) (string, error) {
	// Convert QualifiedCaps to a slice of strings
	var qualifiedCapsStrings []string
	for i, qc := range caps.QualifiedCaps {
		qualifiedCapToString, err := qualifiedCapToString(qc)
		if err != nil {
			return "", err
		}
		qualifiedCapsStrings = append(qualifiedCapsStrings, qualifiedCapToString)
		if i < len(caps.QualifiedCaps)-1 {
			qualifiedCapsStrings = append(qualifiedCapsStrings, ",")
		}
	}

	// Concatenate fields into a single string
	result := fmt.Sprintf("{\"name\":\"%s\",\"qualifiedcaps\":[%s]}", caps.Name, strings.Join(qualifiedCapsStrings, ""))
	return result, nil
}

// StringToCapabilities parses a JSON string and returns a Capabilities struct.
func StringToCapabilities(jsonStr string) (types.Capabilities, error) {
	var caps types.Capabilities
	err := json.Unmarshal([]byte(jsonStr), &caps)
	return caps, err
}

// Function to remove a qualified capability based on its ID
func RemoveQualifiedCapability(caps types.Capabilities, idToRemove string) (string, error) {
	var qualifiedCapsStrings []string

	for i, qc := range caps.QualifiedCaps {
		if qc.Id != idToRemove {
			qualifiedCapToString, err := qualifiedCapToString(qc)
			if err != nil {
				return "", err
			}
			qualifiedCapsStrings = append(qualifiedCapsStrings, qualifiedCapToString)
			if i < len(caps.QualifiedCaps)-1 {
				qualifiedCapsStrings = append(qualifiedCapsStrings, ",")
			}
		}
	}
	// Concatenate fields into a single string
	result := fmt.Sprintf("{\"name\":\"%s\",\"qualifiedcaps\":[%s]}", caps.Name, strings.Join(qualifiedCapsStrings, ""))
	return result, nil
}
