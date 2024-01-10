package types

type AppConfig struct {
	DBConnURL        string `json:"db_conn_url"`
	DBHost           string `json:"db_host"`
	DBPort           int    `json:"db_port"`
	DBUser           string `json:"db_user"`
	DBPassword       string `json:"db_password"`
	DBName           string `json:"db_name"`
	AppServerPort    string `json:"app_server_port"`
	ProviderUrl      string `json:"provider_url"`
	KeycloakURL      string `json:"keycloak_url"`
	KeycloakClientID string `json:"keycloak_client_id"`
}

type OpReq struct {
	User      string   `json:"user"`
	CapNeeded []string `json:"capNeeded"`
	Scope     Scope    `json:"scope"`
	Limit     Limit    `json:"limit"`
}

type Scope map[string]interface{}
type Limit map[string]interface{}

type QualifiedCap struct {
	Id    string `json:"id"`
	Cap   string `json:"cap"`
	Scope Scope  `json:"scope"`
	Limit Limit  `json:"limit"`
}

type Capabilities struct {
	Name          string         `json:"name"` //either user name or group name
	QualifiedCaps []QualifiedCap `json:"qualifiedcaps"`
}