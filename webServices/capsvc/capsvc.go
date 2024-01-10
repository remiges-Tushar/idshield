package capsvc

import (
	"fmt"
	"strings"

	"github.com/Nerzal/gocloak/v13"
	"github.com/gin-gonic/gin"
	"github.com/remiges-tech/alya/router"
	"github.com/remiges-tech/alya/service"
	"github.com/remiges-tech/alya/wscutils"
	"github.com/remiges-tech/idshield/types"
	"github.com/remiges-tech/idshield/utils"
	"github.com/remiges-tech/logharbour/logharbour"
)

type capRevoke struct {
	User string `json:"user" validate:"required"`
	Cap  string `json:"cap" validate:"required"`
}

// capuser_grant() is granting capabilities to user
func Capuser_grant(c *gin.Context, s *service.Service) {
	l := s.LogHarbour
	l.Log("Starting execution of Capuser_grant()")
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
		CapNeeded: []string{"Capuser_grant"},
	}, false)

	if !isCapable {
		l.Log("Unauthorized user:")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrUnauthorized))
		return
	}

	var ucap types.Capabilities

	// Unmarshal JSON request into user struct
	if err = wscutils.BindJSON(c, &ucap); err != nil {
		l.LogActivity("Error Unmarshalling JSON to struct:", logharbour.DebugInfo{Variables: map[string]any{"Error": err.Error()}})
		return
	}

	// Extracting the GoCloak client from the service dependencies
	gcClient, ok := s.Dependencies["gocloak"].(*gocloak.GoCloak)
	if !ok {
		l.Log("Failed to load the dependency to *gocloak.GoCloak")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrFailedToLoadDependence))
		return
	}

	users, err := gcClient.GetUsers(c, token, realm, gocloak.GetUsersParams{
		Username: &ucap.Name,
	})
	if err != nil {
		utils.GocloakErrorHandler(c, l, err)
		return
	}
	if len(users) == 0 {
		l.Log("Error while gcClient.GetUsers user doesn't exist ")
		str := "name"
		wscutils.SendErrorResponse(c, wscutils.NewResponse("error", nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(utils.ErrNotExist, &str)}))
		return
	}

	capabilitiesToString, err := utils.CapabilitiesToString(ucap)
	if err != nil {
		l.Debug0().LogDebug("Error while converting Capabilities To String:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse("Error while converting Capabilities To String"))
		return
	}
	fmt.Println("len", len(capabilitiesToString))

	attr := map[string][]string{
		"qualifiedcaps": {capabilitiesToString},
	}

	keycloakUser := gocloak.User{
		ID:         users[0].ID,
		Attributes: &attr,
	}

	err = gcClient.UpdateUser(c, token, realm, keycloakUser)
	if err != nil {
		l.LogActivity("Error while granting cap:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		utils.GocloakErrorHandler(c, l, err)
		return
	}

	// Send success response
	wscutils.SendSuccessResponse(c, &wscutils.Response{Status: wscutils.SuccessStatus, Data: "Grant Capabilities successfully ", Messages: []wscutils.ErrorMessage{}})

	l.Log("Finished execution of Capuser_grant()")
}

// capuser_revoke() is revoking capabilities to user
func Capuser_revoke(c *gin.Context, s *service.Service) {
	l := s.LogHarbour
	l.Log("Starting execution of Capuser_revoke()")
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
		CapNeeded: []string{"Capuser_revoke"},
	}, false)

	if !isCapable {
		l.Log("Unauthorized user:")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrUnauthorized))
		return
	}

	var userCapRevoke capRevoke

	// Unmarshal JSON request into user struct
	if err = wscutils.BindJSON(c, &userCapRevoke); err != nil {
		l.LogActivity("Error Unmarshalling JSON to struct:", logharbour.DebugInfo{Variables: map[string]any{"Error": err.Error()}})
		return
	}

	// Extracting the GoCloak client from the service dependencies
	gcClient, ok := s.Dependencies["gocloak"].(*gocloak.GoCloak)
	if !ok {
		l.Log("Failed to load the dependency to *gocloak.GoCloak")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrFailedToLoadDependence))
		return
	}

	users, err := gcClient.GetUsers(c, token, realm, gocloak.GetUsersParams{
		Username: &userCapRevoke.User,
	})
	if err != nil {
		utils.GocloakErrorHandler(c, l, err)
		return
	}
	if len(users) == 0 {
		l.Log("Error while gcClient.GetUsers user doesn't exist ")
		str := "name"
		wscutils.SendErrorResponse(c, wscutils.NewResponse("error", nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(utils.ErrNotExist, &str)}))
		return
	}
	caps := *users[0].Attributes
	capstruct, err := utils.StringToCapabilities((caps["qualifiedcaps"])[0])
	if err != nil {
		l.Debug0().LogDebug("error while converting StringToCapabilities: ", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse("error while converting StringToCapabilities"))
		return
	}

	atrr, err := utils.RemoveQualifiedCapability(capstruct, userCapRevoke.Cap)
	if err != nil {
		l.Debug0().LogDebug("error while Remove Qualified Capability: ", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse("error while Remove Qualified Capability"))
		return
	}

	attr := map[string][]string{
		"qualifiedcaps": {atrr},
	}

	keycloakUser := gocloak.User{
		ID:         users[0].ID,
		Attributes: &attr,
	}

	err = gcClient.UpdateUser(c, token, realm, keycloakUser)
	if err != nil {
		l.LogActivity("Error while revoking cap:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		utils.GocloakErrorHandler(c, l, err)
		return
	}

	// Send success response
	wscutils.SendSuccessResponse(c, &wscutils.Response{Status: wscutils.SuccessStatus, Data: "Revoke Capabilities successfully ", Messages: []wscutils.ErrorMessage{}})

	l.Log("Finished execution of Capuser_revoke()")
}

// Capuser_getall() is for getting all capabilities for user
func Capuser_getall(c *gin.Context, s *service.Service) {
	l := s.LogHarbour
	l.Log("Starting execution of Capuser_getall()")
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
		CapNeeded: []string{"Capuser_getall"},
	}, false)

	if !isCapable {
		l.Log("Unauthorized user:")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrUnauthorized))
		return
	}

	user, ok := c.GetQuery("user")
	if !ok {
		l.Log("Error while geting parma:")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrInvalidParam))
		return
	}

	// Extracting the GoCloak client from the service dependencies
	gcClient, ok := s.Dependencies["gocloak"].(*gocloak.GoCloak)
	if !ok {
		l.Log("Failed to load the dependency to *gocloak.GoCloak")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrFailedToLoadDependence))
		return
	}

	users, err := gcClient.GetUsers(c, token, realm, gocloak.GetUsersParams{
		Username: &user,
	})
	if err != nil {
		utils.GocloakErrorHandler(c, l, err)
		return
	}
	if len(users) == 0 || !strings.EqualFold(*users[0].Username, user) {
		l.Log("Error while gcClient.GetUsers user doesn't exist ")
		str := "name"
		wscutils.SendErrorResponse(c, wscutils.NewResponse("error", nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(utils.ErrNotExist, &str)}))
		return
	}

	if users[0].Attributes != nil {
		caps := *users[0].Attributes
		capstruct, err := utils.StringToCapabilities((caps["qualifiedcaps"])[0])
		if err != nil {
			l.Debug0().LogDebug("error while converting StringToCapabilities: ", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
			wscutils.SendErrorResponse(c, wscutils.NewErrorResponse("error while converting StringToCapabilities"))
			return
		}
		wscutils.SendSuccessResponse(c, &wscutils.Response{Status: wscutils.SuccessStatus, Data: capstruct, Messages: []wscutils.ErrorMessage{}})
	} else {
		wscutils.SendSuccessResponse(c, &wscutils.Response{Status: wscutils.SuccessStatus, Data: "no user cap found", Messages: []wscutils.ErrorMessage{}})
	}
	l.Log("Finished execution of Capuser_getall()")
}

// capgroup_grant() is granting capabilities to group
func Capgroup_grant(c *gin.Context, s *service.Service) {
	l := s.LogHarbour
	l.Log("Starting execution of capgroup_grant()")
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
		CapNeeded: []string{"capgroup_grant"},
	}, false)

	if !isCapable {
		l.Log("Unauthorized user:")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrUnauthorized))
		return
	}

	var gcap types.Capabilities

	// Unmarshal JSON request into user struct
	if err = wscutils.BindJSON(c, &gcap); err != nil {
		l.LogActivity("Error Unmarshalling JSON to struct:", logharbour.DebugInfo{Variables: map[string]any{"Error": err.Error()}})
		return
	}

	// Extracting the GoCloak client from the service dependencies
	gcClient, ok := s.Dependencies["gocloak"].(*gocloak.GoCloak)
	if !ok {
		l.Log("Failed to load the dependency to *gocloak.GoCloak")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrFailedToLoadDependence))
		return
	}

	groups, err := gcClient.GetGroups(c, token, realm, gocloak.GetGroupsParams{
		Search: &gcap.Name,
	})
	if err != nil {
		utils.GocloakErrorHandler(c, l, err)
		return
	}
	if len(groups) == 0 {
		l.Log("Error while gcClient.GetGroups group doesn't exist ")
		str := "name"
		wscutils.SendErrorResponse(c, wscutils.NewResponse("error", nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(utils.ErrNotExist, &str)}))
		return
	}

	capabilitiesToString, err := utils.CapabilitiesToString(gcap)
	if err != nil {
		l.Debug0().LogDebug("Error while converting Capabilities To String:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse("Error while converting Capabilities To String"))
		return
	}
	attr := map[string][]string{
		"qualifiedcaps": {capabilitiesToString},
	}

	updatedGroup := gocloak.Group{
		ID:         groups[0].ID,
		Name:       groups[0].Name,
		Attributes: &attr,
	}

	err = gcClient.UpdateGroup(c, token, realm, updatedGroup)
	if err != nil {
		l.LogActivity("Error while granting cap to group:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		utils.GocloakErrorHandler(c, l, err)
		return
	}

	// Send success response
	wscutils.SendSuccessResponse(c, &wscutils.Response{Status: wscutils.SuccessStatus, Data: "Grant Capabilities to group successfully ", Messages: []wscutils.ErrorMessage{}})

	l.Log("Finished execution of Capgroup_grant()")
}

// Capgroup_revoke() is revoking capabilities to group
func Capgroup_revoke(c *gin.Context, s *service.Service) {
	l := s.LogHarbour
	l.Log("Starting execution of Capgroup_revoke()")
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
		CapNeeded: []string{"Capgroup_revoke"},
	}, false)

	if !isCapable {
		l.Log("Unauthorized user:")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrUnauthorized))
		return
	}

	var groupCapRevoke capRevoke

	// Unmarshal JSON request into user struct
	if err = wscutils.BindJSON(c, &groupCapRevoke); err != nil {
		l.LogActivity("Error Unmarshalling JSON to struct:", logharbour.DebugInfo{Variables: map[string]any{"Error": err.Error()}})
		return
	}

	// Extracting the GoCloak client from the service dependencies
	gcClient, ok := s.Dependencies["gocloak"].(*gocloak.GoCloak)
	if !ok {
		l.Log("Failed to load the dependency to *gocloak.GoCloak")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrFailedToLoadDependence))
		return
	}

	groups, err := gcClient.GetGroups(c, token, realm, gocloak.GetGroupsParams{
		Search: &groupCapRevoke.User,
	})
	if err != nil {
		utils.GocloakErrorHandler(c, l, err)
		return
	}
	if len(groups) == 0 || !strings.EqualFold(*groups[0].Name, groupCapRevoke.User) {
		l.Log("Error while gcClient.GetGroups group doesn't exist ")
		str := "name"
		wscutils.SendErrorResponse(c, wscutils.NewResponse("error", nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(utils.ErrNotExist, &str)}))
		return
	}
	group, err := gcClient.GetGroup(c, token, realm, *groups[0].ID)
	if err != nil {
		l.Log("Error while getting group gcClient.GetGroup:")
		str := "name"
		wscutils.SendErrorResponse(c, wscutils.NewResponse("error", nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(utils.ErrNotExist, &str)}))
		return
	}

	caps := *group.Attributes
	capstruct, err := utils.StringToCapabilities((caps["qualifiedcaps"])[0])
	if err != nil {
		l.Debug0().LogDebug("error while converting StringToCapabilities: ", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse("error while converting StringToCapabilities"))
		return
	}

	atrr, err := utils.RemoveQualifiedCapability(capstruct, groupCapRevoke.Cap)
	if err != nil {
		l.Debug0().LogDebug("error while Remove Qualified Capability: ", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse("error while Remove Qualified Capability"))
		return
	}

	attr := map[string][]string{
		"qualifiedcaps": {atrr},
	}

	updatedGroup := gocloak.Group{
		ID:         group.ID,
		Name:       group.Name,
		Attributes: &attr,
	}

	err = gcClient.UpdateGroup(c, token, realm, updatedGroup)
	if err != nil {
		l.LogActivity("Error while revoking cap in group:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		utils.GocloakErrorHandler(c, l, err)
		return
	}

	// Send success response
	wscutils.SendSuccessResponse(c, &wscutils.Response{Status: wscutils.SuccessStatus, Data: "Revoke Capabilities successfully ", Messages: []wscutils.ErrorMessage{}})

	l.Log("Finished execution of Capuser_revoke()")
}

// Capgroup_getall() is for getting all capabilities for group
func Capgroup_getall(c *gin.Context, s *service.Service) {
	l := s.LogHarbour
	l.Log("Starting execution of Capgroup_getall()")
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
		CapNeeded: []string{"Capgroup_getall"},
	}, false)

	if !isCapable {
		l.Log("Unauthorized user:")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrUnauthorized))
		return
	}

	groupName, ok := c.GetQuery("group")
	if !ok {
		l.Log("Error while geting parma:")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrInvalidParam))
		return
	}

	// Extracting the GoCloak client from the service dependencies
	gcClient, ok := s.Dependencies["gocloak"].(*gocloak.GoCloak)
	if !ok {
		l.Log("Failed to load the dependency to *gocloak.GoCloak")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrFailedToLoadDependence))
		return
	}

	groups, err := gcClient.GetGroups(c, token, realm, gocloak.GetGroupsParams{
		Search: &groupName,
	})
	if err != nil {
		utils.GocloakErrorHandler(c, l, err)
		return
	}
	if len(groups) == 0 || !strings.EqualFold(*groups[0].Name, groupName) {
		l.Log("Error while gcClient.GetUsers user doesn't exist ")
		str := "name"
		wscutils.SendErrorResponse(c, wscutils.NewResponse("error", nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(utils.ErrNotExist, &str)}))
		return
	}

	group, err := gcClient.GetGroup(c, token, realm, *groups[0].ID)
	if err != nil {
		l.Log("Error while getting group gcClient.GetGroup:")
		str := "name"
		wscutils.SendErrorResponse(c, wscutils.NewResponse("error", nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(utils.ErrNotExist, &str)}))
		return
	}

	if group.Attributes != nil {
		caps := *group.Attributes
		capstruct, err := utils.StringToCapabilities(caps["qualifiedcaps"][0])
		if err != nil {
			l.Debug0().LogDebug("error while converting StringToCapabilities: ", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
			wscutils.SendErrorResponse(c, wscutils.NewErrorResponse("error while converting StringToCapabilities"))
			return
		}
		wscutils.SendSuccessResponse(c, &wscutils.Response{Status: wscutils.SuccessStatus, Data: capstruct, Messages: []wscutils.ErrorMessage{}})
	} else {
		wscutils.SendSuccessResponse(c, &wscutils.Response{Status: wscutils.SuccessStatus, Data: "no group cap found", Messages: []wscutils.ErrorMessage{}})
	}

	l.Log("Finished execution of Capgroup_getall()")
}
