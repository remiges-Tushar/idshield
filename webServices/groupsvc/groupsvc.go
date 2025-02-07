package groupsvc

import (
	"fmt"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/remiges-tech/alya/router"
	"github.com/remiges-tech/alya/service"
	"github.com/remiges-tech/alya/wscutils"
	"github.com/remiges-tech/idshield/types"
	"github.com/remiges-tech/idshield/utils"
	"github.com/remiges-tech/logharbour/logharbour"
)

type group struct {
	ID         string            `json:"id,omitempty"`
	ShortName  string            `json:"shortName" validate:"required"`
	LongName   string            `json:"longName" validate:"required"`
	Attributes map[string]string `json:"attr" validate:"required"`
}

type groupListResponse struct {
	ShortName *string `json:"shortName,omitempty"`
	LongName  *string `json:"longName,omitempty"`
	Nusers    int     `json:"nusers"`
}
type groupResponse struct {
	ID          *string              `json:"id,omitempty"`
	Name        *string              `json:"name,omitempty"`
	Path        *string              `json:"path,omitempty"`
	SubGroups   *[]gocloak.Group     `json:"subGroups,omitempty"`
	Attributes  *map[string][]string `json:"attributes,omitempty"`
	Access      *map[string]bool     `json:"access,omitempty"`
	ClientRoles *map[string][]string `json:"clientRoles,omitempty"`
	RealmRoles  *[]string            `json:"realmRoles,omitempty"`
	Nusers      int                  `json:"nusers,omitempty"`
	CreatedAt   time.Time            `json:"createdat,omitempty"`
}

func Group_new(c *gin.Context, s *service.Service) {
	l := s.LogHarbour
	l.Log("Starting execution of Group_new()")

	token, err := router.ExtractToken(c.GetHeader("Authorization"))
	if err != nil {
		l.Debug0().LogDebug("Missing or incorrect Authorization header format:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrTokenMissing))
		return
	}
	r, err := utils.ExtractClaimFromJwt(token, "iss")
	if err != nil {
		l.Debug0().LogDebug("Missing or incorrect realm:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrRealmNotFound))
		return
	}
	parts := strings.Split(r, "/realms/")
	realm := parts[1]
	username, err := utils.ExtractClaimFromJwt(token, "preferred_username")
	if err != nil {
		l.Debug0().LogDebug("Missing username:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrUserNotFound))
		return
	}

	isCapable, _ := utils.Authz_check(types.OpReq{
		User:      username,
		CapNeeded: []string{"GroupCreate"},
	}, false)

	if !isCapable {
		l.Log("Unauthorized user:")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrUnauthorized))
		return
	}

	var g group

	if err := wscutils.BindJSON(c, &g); err != nil {
		l.LogActivity("Error Unmarshalling JSON to struct:", logharbour.DebugInfo{Variables: map[string]any{"Error": err.Error()}})
		return
	}

	//Validate incoming request
	validationErrors := validateGroup(c, g)
	if len(validationErrors) > 0 {
		l.Debug0().LogDebug("Validation errors:", logharbour.DebugInfo{Variables: map[string]interface{}{"validationErrors": validationErrors}})
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, validationErrors))
		return
	}

	// Extracting the GoCloak client from the service dependencies
	gcClient, ok := s.Dependencies["gocloak"].(*gocloak.GoCloak)
	if !ok {
		l.Log("Failed to convert the dependency to *gocloak.GoCloak")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrFailedToLoadDependence))
	}
	attr := make(map[string][]string)
	for key, value := range g.Attributes {
		attr[key] = []string{value}
	}

	attr["longName"] = []string{g.LongName}

	group := gocloak.Group{
		Name:       &g.ShortName,
		Attributes: &attr,
	}

	// Create a group
	ID, err := gcClient.CreateGroup(c, token, realm, group)
	if err != nil {
		l.LogActivity("Error while creating user:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, &wscutils.Response{Data: err})
		return
	}

	// Send success response
	wscutils.SendSuccessResponse(c, &wscutils.Response{Status: "success", Data: ID})

	// Log the completion of execution
	l.Log("Finished execution of Group_new()")
}

// Group_get: handles the GET /groupget request, this will accept short group name if it exist will return single group
func Group_get(c *gin.Context, s *service.Service) {
	lh := s.LogHarbour
	lh.Log("Group_get request received")
	client := s.Dependencies["gocloak"].(*gocloak.GoCloak)
	var groupParams gocloak.GetGroupsParams

	token, err := router.ExtractToken(c.GetHeader("Authorization")) // separate "Bearer_" word from token
	lh.Log("token extracted from header")
	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(wscutils.ErrcodeMissing, nil, "token")}))
		lh.Debug0().Log(fmt.Sprintf("token_missing: %v", map[string]any{"error": err.Error()}))
		return
	}

	// retrive username from token for isCapable check
	reqUserName, _ := utils.ExtractClaimFromJwt(token, "preferred_username")

	// Authz_check():
	isCapable, _ := utils.Authz_check(types.OpReq{User: reqUserName, CapNeeded: []string{"devloper", "admin"}}, false)
	if !isCapable {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage("User_not_authorized_to_perform_this_action", nil)}))
		lh.Debug0().Log("User_not_authorized_to_perform_this_action")
		return
	}

	realm, err := utils.ExtractClaimFromJwt(token, "iss")
	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage("invalid_token_payload", &realm)}))
		lh.Debug0().Log(fmt.Sprintf("invalid token payload: %v", map[string]any{"error": err.Error()}))
		return
	}
	split := strings.Split(realm, "/")
	realm = split[len(split)-1]

	lh.Log(fmt.Sprintf("Group_get realm parsed: %v", map[string]any{"realm": realm}))
	if gocloak.NilOrEmpty(&realm) {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage("realm_not_found", &realm)}))
		lh.Debug0().Log(fmt.Sprintf("realm_not_found: %v", map[string]any{"realm": realm}))
		return
	}

	shortName := c.Query("shortName")
	if gocloak.NilOrEmpty(&shortName) {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(wscutils.ErrcodeMissing, nil, "shortName")}))
		lh.Debug0().Log("shortName missing")
		return
	}
	// step 4: process the request
	// Search given shortName in groups and store it's ID and PATH
	groupParams.Search = &shortName
	groups, err := client.GetGroups(c, token, realm, groupParams)
	lh.Log("GetGroups() request received")

	// if err or response is empty then no group with given name, Hence return
	if err != nil || len(groups) == 0 {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage("group_not_found", &realm)}))
		lh.Debug0().Log(fmt.Sprintf("group not found in given realm error: %v", map[string]any{"realm": realm}))
		return
	}
	// if group found then only you will be here, hence ignore the err & get the details of that group with path including attributes
	group, _ := client.GetGroupByPath(c, token, realm, *groups[0].Path)

	grpResp := groupResponse{
		ID:          group.ID,
		Name:        group.Name,
		SubGroups:   group.SubGroups,
		Attributes:  group.Attributes,
		Access:      group.Access,
		ClientRoles: group.ClientRoles,
		RealmRoles:  group.RealmRoles,
		// CreatedAt:   time.Time{},
	}

	// to get the count of the users available in that group
	userCountGroup, _ := client.GetGroupMembers(c, token, realm, *group.ID, groupParams)
	grpResp.Nusers = len(userCountGroup)

	// step 5: if there are no errors, send success response
	lh.Log(fmt.Sprintf("Group found: %v", grpResp))
	wscutils.SendSuccessResponse(c, wscutils.NewSuccessResponse(grpResp))
}

// HandleCreateUserRequest is for updating group capabilities.
func Group_update(c *gin.Context, s *service.Service) {
	l := s.LogHarbour
	l.Log("Starting execution of Group_update() ")
	token, err := router.ExtractToken(c.GetHeader("Authorization"))
	if err != nil {
		l.Debug0().LogDebug("Missing or incorrect Authorization header format:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrTokenMissing))
		return
	}
	r, err := utils.ExtractClaimFromJwt(token, "iss")
	if err != nil {
		l.Debug0().LogDebug("Missing or incorrect realm:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrRealmNotFound))
		return
	}
	parts := strings.Split(r, "/realms/")
	realm := parts[1]
	username, err := utils.ExtractClaimFromJwt(token, "preferred_username")
	if err != nil {
		l.Debug0().LogDebug("Missing username:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrUserNotFound))
		return
	}

	isCapable, _ := utils.Authz_check(types.OpReq{
		User:      username,
		CapNeeded: []string{"GroupUpdate"},
	}, false)

	if !isCapable {
		l.Log("Unauthorized user:")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrUnauthorized))
		return
	}

	var g group

	// Unmarshal JSON request into group struct
	err = wscutils.BindJSON(c, &g)
	if err != nil {
		l.LogActivity("Error Unmarshalling JSON to struct:", logharbour.DebugInfo{Variables: map[string]any{"Error": err.Error()}})
		return
	}

	// Validate the group struct
	validationErrors := validateGroup(c, g)
	if len(validationErrors) > 0 {
		l.Debug0().LogDebug("Validation errors:", logharbour.DebugInfo{Variables: map[string]any{"validationErrors": validationErrors}})
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, validationErrors))
		return
	}

	// Extracting the GoCloak client from the service dependencies
	gcClient, ok := s.Dependencies["gocloak"].(*gocloak.GoCloak)
	if !ok {
		l.Log("Failed to convert the dependency to *gocloak.GoCloak")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrFailedToLoadDependence))
	}

	groups, err := gcClient.GetGroups(c, token, realm, gocloak.GetGroupsParams{
		Search: &g.ShortName,
	})
	if err != nil {
		utils.GocloakErrorHandler(c, l, err)
		return
	}
	if len(groups) == 0 {
		l.Log("Error while gcClient.GetGroups Group doesn't exist ")
		str := "shortName"
		wscutils.SendErrorResponse(c, wscutils.NewResponse("error", nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(utils.ErrNotExist, &str)}))
		return
	}
	attr := make(map[string][]string)
	for key, value := range g.Attributes {
		attr[key] = []string{value}
	}

	attr["longName"] = []string{g.LongName}

	UpdateGroupParm := gocloak.Group{
		ID:         groups[0].ID,
		Name:       &g.ShortName,
		Attributes: &attr,
	}
	// UpdateGroup updates the given group by group name
	err = gcClient.UpdateGroup(c, token, realm, UpdateGroupParm)
	if err != nil {
		l.LogActivity("Error while creating user:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, &wscutils.Response{Data: err})
		return
	}

	// Send success response
	wscutils.SendSuccessResponse(c, &wscutils.Response{Status: "success"})

	l.Log("Finished update Group_Update()")
}

// Group_list handles the GET /grouplist request
func Group_list(c *gin.Context, s *service.Service) {
	lh := s.LogHarbour
	lh.Log("Group_list request received")
	var listResponse []groupListResponse

	client := s.Dependencies["gocloak"].(*gocloak.GoCloak)

	token, err := router.ExtractToken(c.GetHeader("Authorization")) // separate "Bearer " word from token
	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(wscutils.ErrcodeMissing, nil, "token")}))
		lh.Debug0().LogActivity("token_missing", map[string]any{"error": err.Error()})
		return
	}
	lh.Log("token extracted from header")

	reqUserName, err := utils.ExtractClaimFromJwt(token, "preferred_username")
	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(wscutils.ErrcodeMissing, nil, "preferred_username")}))
		lh.LogActivity("Error while extracting preferred_username from token:", logharbour.DebugInfo{Variables: map[string]any{"preferred_username": err.Error()}})
		return
	}
	// Authz_check():
	isCapable, _ := utils.Authz_check(types.OpReq{User: reqUserName, CapNeeded: []string{"devloper", "admin"}}, false)
	if !isCapable {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(utils.ErrUserNotAuthorized, nil)}))
		lh.Debug0().Log(utils.ErrUserNotAuthorized)
		return
	}

	realm := utils.GetRealmFromJwt(c, token)
	if gocloak.NilOrEmpty(&realm) {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(utils.ErrRealmNotFound, &realm)}))
		lh.Debug0().LogActivity("realm_not_found :", map[string]any{"realm": realm})
		return
	}
	lh.LogActivity("User_update realm parsed: %v", map[string]any{"realm": realm})

	// step 4: process the request
	groups, err := client.GetGroups(c, token, realm, gocloak.GetGroupsParams{})

	if err != nil || len(groups) == 0 {
		switch err.Error() {
		case utils.ErrHTTPUnauthorized:
			wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(wscutils.ErrcodeTokenVerificationFailed, &realm, err.Error())}))
			lh.Debug0().LogActivity("token expired error from keycloak :", map[string]any{"error": err.Error()})
		default:
			wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(utils.ErrUserNotFound, &realm, err.Error())}))
			lh.Debug0().LogActivity("user not found in given realm :", map[string]any{"realm": realm, "error": err.Error()})
		}
		return
	}

	for _, eachGroup := range groups {
		// setting response fields
		eachGrpRep := groupListResponse{
			ShortName: eachGroup.Path,
			LongName:  eachGroup.Name,
		}

		// to get the count of the users available in that group
		userCountGroup, _ := client.GetGroupMembers(c, token, realm, *eachGroup.ID, gocloak.GetGroupsParams{})
		eachGrpRep.Nusers = len(userCountGroup)

		listResponse = append(listResponse, eachGrpRep)
	}
	// step 5: if there are no errors, send success response
	wscutils.SendSuccessResponse(c, wscutils.NewSuccessResponse(map[string]any{"groups": listResponse}))
}

// validateCreateUser performs validation for the createUserRequest.
func validateGroup(c *gin.Context, g group) []wscutils.ErrorMessage {
	// Validate the request body
	validationErrors := wscutils.WscValidate(g, g.getValsForGroup)

	if len(validationErrors) > 0 {
		return validationErrors
	}
	return validationErrors
}

// getValsForUser returns validation error details based on the field and tag.
func (g *group) getValsForGroup(err validator.FieldError) []string {
	var vals []string
	switch err.Field() {
	case "Name":
		switch err.Tag() {
		case "required":
			vals = append(vals, "non-empty")
			vals = append(vals, g.ShortName)
		}
	case "LongName":
		switch err.Tag() {
		case "required":
			vals = append(vals, "non-empty")
			vals = append(vals, g.LongName)
		}
	case "Attributes":
		switch err.Tag() {
		case "required":
			vals = append(vals, "non-empty")
			vals = append(vals, " ")
		}
	}
	return vals
}
