package server

// Service defines config for a specific service being gated
// by the API Gateway app.
type Service struct {
	Name    string
	BaseURI string
}

// Route defines config for a specific route for a Service.
type Route struct {
	Path    string
	Filters []string
}
