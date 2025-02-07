package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/Nerzal/gocloak/v13"
	"github.com/remiges-tech/alya/config"
	"github.com/remiges-tech/alya/logger"
	"github.com/remiges-tech/alya/router"
	"github.com/remiges-tech/alya/service"
	"github.com/remiges-tech/alya/wscutils"
	"github.com/remiges-tech/idshield/webServices/capsvc"
	"github.com/remiges-tech/idshield/webServices/groupsvc"
	"github.com/remiges-tech/idshield/webServices/usersvc"
	"github.com/remiges-tech/logharbour/logharbour"
)

// AppConfig represents the configuration structure for the application.
type AppConfig struct {
	AppServerPort    string `json:"app_server_port"`
	ProviderURL      string `json:"provider_url"`
	KeycloakURL      string `json:"keycloak_url"`
	Realm            string `json:"realm"`
	KeycloakClientID string `json:"keycloak_client_id"`
}

func main() {
	// Command-line flags for configuration options
	configSystem := flag.String("configSource", "file", "The configuration system to use (file or rigel)")
	configFilePath := flag.String("configFile", "./config.json", "The path to the configuration file")
	rigelConfigName := flag.String("configName", "C1", "The name of the configuration")
	rigelSchemaName := flag.String("schemaName", "S1", "The name of the schema")
	etcdEndpoints := flag.String("etcdEndpoints", "localhost:2379", "Comma-separated list of etcd endpoints")

	flag.Parse()

	// Initialize configuration struct
	var appConfig AppConfig

	// Load configuration based on the specified system
	switch *configSystem {
	case "file":
		err := config.LoadConfigFromFile(*configFilePath, &appConfig)
		if err != nil {
			log.Fatalf("Error loading config: %v", err)
		}
	case "rigel":
		err := config.LoadConfigFromRigel(*etcdEndpoints, *rigelConfigName, *rigelSchemaName, &appConfig)
		if err != nil {
			log.Fatalf("Error loading config: %v", err)
		}
	default:
		log.Fatalf("Unknown configuration system: %s", *configSystem)
	}

	// Print the loaded configuration
	fmt.Printf("Loaded configuration: %+v\n", appConfig)

	// Open and load error types from the file
	file, err := os.Open("./errortypes.yaml")
	if err != nil {
		log.Fatalf("Failed to open error types file: %v", err)
	}
	defer file.Close()

	wscutils.LoadErrorTypes(file)

	// Logger setup
	logFile, err := os.OpenFile("log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	fallbackWriter := logharbour.NewFallbackWriter(logFile, os.Stdout)
	lctx := logharbour.NewLoggerContext(logharbour.Info)
	lh := logharbour.NewLogger(lctx, "idshield", fallbackWriter)
	fl := logger.NewFileLogger("/tmp/idshield.log")

	// Redis token cache setup
	cache := router.NewRedisTokenCache("localhost:6379", "", 0, 0)

	// Authentication middleware setup
	authMiddleware, err := router.LoadAuthMiddleware(appConfig.KeycloakClientID, appConfig.ProviderURL, cache, fl)
	if err != nil {
		log.Fatalf("Failed to create new auth middleware: %v", err)
	}

	// Router setup
	r, err := router.SetupRouter(true, fl, authMiddleware)
	if err != nil {
		log.Fatalf("Failed to setup router: %v", err)
	}

	// Create a gocloak client
	gcClient := gocloak.NewClient(appConfig.KeycloakURL)

	// Service setup
	s := service.NewService(r).WithDependency("gocloak", gcClient).WithLogHarbour(lh).WithDependency("realm", appConfig.Realm)

	// Register a route for handling for user
	s.RegisterRoute(http.MethodGet, "/userlist", usersvc.User_list)
	s.RegisterRoute(http.MethodDelete, "/userdelete", usersvc.User_delete)
	s.RegisterRoute(http.MethodPut, "/userupdate", usersvc.User_update)
	s.RegisterRoute(http.MethodGet, "/userget", usersvc.User_get)
	s.RegisterRoute(http.MethodPost, "/usernew", usersvc.User_new)
	s.RegisterRoute(http.MethodPost, "/useractivate", usersvc.User_activate)
	s.RegisterRoute(http.MethodPost, "/userdeactivate", usersvc.User_deactivate)

	// Register a route for handling for group
	s.RegisterRoute(http.MethodPost, "/groupnew", groupsvc.Group_new)
	s.RegisterRoute(http.MethodGet, "/groupget", groupsvc.Group_get)
	s.RegisterRoute(http.MethodPost, "/groupupdate", groupsvc.Group_update)
	s.RegisterRoute(http.MethodGet, "/grouplist", groupsvc.Group_list)

	// Register a route for handling capabilities
	s.RegisterRoute(http.MethodPost, "/capusergrant", capsvc.Capuser_grant)
	s.RegisterRoute(http.MethodPost, "/capuserrevoke", capsvc.Capuser_revoke)
	s.RegisterRoute(http.MethodGet, "/capusergetall", capsvc.Capuser_getall)

	s.RegisterRoute(http.MethodPost, "/capgroupgrant", capsvc.Capgroup_grant)
	s.RegisterRoute(http.MethodPost, "/capgrouprevoke", capsvc.Capgroup_revoke)
	s.RegisterRoute(http.MethodGet, "/capgroupgetall", capsvc.Capgroup_getall)

	// Start the service
	if err := r.Run(":" + appConfig.AppServerPort); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
