package cli

import (
	"strings"
	"testing"
)

func TestInspector_InspectStdin(t *testing.T) {
	ins := NewInspector()

	tests := []struct {
		name       string
		data       []byte
		wantClean  bool
		wantSubstr string // if not clean, at least one concern should contain this
	}{
		{
			name:      "empty input",
			data:      nil,
			wantClean: true,
		},
		{
			name:      "clean text",
			data:      []byte("hello world\nnothing sensitive here"),
			wantClean: true,
		},
		{
			name:       "OpenAI API key",
			data:       []byte("export OPENAI_KEY=sk-" + "PLACEHOLDER_TEST_VALUE_000000000000000"),
			wantSubstr: "OpenAI API key",
		},
		{
			name:       "AWS access key",
			data:       []byte("aws_key=" + "AKIA" + "IOSFODNN7EXAMPLE"),
			wantSubstr: "AWS access key",
		},
		{
			name:       "GitHub token",
			data:       []byte("GITHUB_TOKEN=" + "ghp_" + "ABCDEFGHIJKLMNOPabcdefghijklmnop01234567"),
			wantSubstr: "GitHub personal access token",
		},
		{
			name:       "GitLab token",
			data:       []byte("token=" + "glpat-" + "abcdefghij0123456789"),
			wantSubstr: "GitLab personal access token",
		},
		{
			name:       "Slack bot token",
			data:       []byte("SLACK_TOKEN=xoxb-" + "000000-000000-PLACEHOLDER"),
			wantSubstr: "Slack bot token",
		},
		{
			name:       "Bearer token",
			data:       []byte("Authorization: Bearer " + "PLACEHOLDER_TEST_JWT_TOKEN"),
			wantSubstr: "Bearer token",
		},
		{
			name:       "password assignment",
			data:       []byte("DB_PASSWORD=" + "PLACEHOLDER_TEST_VALUE"),
			wantSubstr: "password assignment",
		},
		{
			name:       "passwd assignment",
			data:       []byte("MYSQL_PASSWD=" + "PLACEHOLDER_TEST_VALUE"),
			wantSubstr: "password assignment",
		},
		{
			name:       "private key header",
			data:       []byte("-----BEGIN RSA PRIVATE KEY-----\nPLACEHOLDER..."),
			wantSubstr: "private key",
		},
		{
			name:       "EC private key header",
			data:       []byte("-----BEGIN EC PRIVATE KEY-----\nPLACEHOLDER..."),
			wantSubstr: "private key",
		},
		{
			name:       "AWS access key ID config",
			data:       []byte("aws_access_key_id = AKIAIOSFODNN7EXAMPLE"),
			wantSubstr: "AWS access key ID",
		},
		{
			name:       "AWS secret access key config",
			data:       []byte("aws_secret_access_key = " + "PLACEHOLDER_TEST_AWS_SECRET_KEY"),
			wantSubstr: "AWS secret access key",
		},
		{
			name:       "PostgreSQL connection string",
			data:       []byte("DATABASE_URL=" + "postgresql://u:p@localhost:5432/mydb"),
			wantSubstr: "PostgreSQL connection string",
		},
		{
			name:       "MongoDB connection string",
			data:       []byte("MONGO_URI=" + "mongodb://u:p@mongo.example.com:27017"),
			wantSubstr: "MongoDB connection string",
		},
		{
			name:       "Redis connection string",
			data:       []byte("REDIS_URL=" + "redis://u:p@redis.example.com:6379"),
			wantSubstr: "Redis connection string",
		},
		{
			name:       "generic secret assignment",
			data:       []byte("MY_SECRET=" + "PLACEHOLDER_TEST_VALUE"),
			wantSubstr: "secret assignment",
		},
		{
			name:       "generic token assignment",
			data:       []byte("AUTH_TOKEN=" + "PLACEHOLDER_TEST_VALUE"),
			wantSubstr: "secret assignment",
		},
		{
			name:       "generic api_key assignment",
			data:       []byte("MY_API_KEY=" + "PLACEHOLDER_TEST_VALUE"),
			wantSubstr: "secret assignment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			concerns := ins.InspectStdin(tt.data)
			if tt.wantClean {
				if len(concerns) != 0 {
					t.Errorf("expected clean, got concerns: %v", concerns)
				}
				return
			}
			if len(concerns) == 0 {
				t.Fatalf("expected concerns containing %q, got none", tt.wantSubstr)
			}
			found := false
			for _, c := range concerns {
				if strings.Contains(c, tt.wantSubstr) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected concern containing %q, got: %v", tt.wantSubstr, concerns)
			}
		})
	}
}

func TestInspector_InspectOutput(t *testing.T) {
	ins := NewInspector()

	tests := []struct {
		name          string
		data          []byte
		wantSafe      bool
		wantSensitive bool
	}{
		{
			name:     "nil output",
			data:     nil,
			wantSafe: true,
		},
		{
			name:     "empty output",
			data:     []byte{},
			wantSafe: true,
		},
		{
			name:     "clean command output",
			data:     []byte("total 42\ndrwxr-xr-x  5 user staff 160 Jan  1 00:00 docs\n"),
			wantSafe: true,
		},
		{
			name:          "output with API key",
			data:          []byte("config loaded: sk-" + "PLACEHOLDER_TEST_VALUE_000000000"),
			wantSafe:      false,
			wantSensitive: true,
		},
		{
			name:          "output with private key",
			data:          []byte("-----BEGIN RSA PRIVATE KEY-----\nPLACEHOLDER...\n-----END RSA PRIVATE KEY-----"),
			wantSafe:      false,
			wantSensitive: true,
		},
		{
			name:          "output with connection string",
			data:          []byte("connecting to " + "postgresql://u:p@db.example.com:5432/prod"),
			wantSafe:      false,
			wantSensitive: true,
		},
		{
			name:     "URL without credentials is safe",
			data:     []byte("fetching https://api.example.com/data"),
			wantSafe: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ins.InspectOutput(tt.data)
			if result.Safe != tt.wantSafe {
				t.Errorf("Safe = %v, want %v", result.Safe, tt.wantSafe)
			}
			if result.SensitiveData != tt.wantSensitive {
				t.Errorf("SensitiveData = %v, want %v", result.SensitiveData, tt.wantSensitive)
			}
		})
	}
}

func TestInspector_InspectOutput_ConcernsContent(t *testing.T) {
	ins := NewInspector()
	data := []byte("sk-" + "PLACEHOLDER_TEST_VALUE_000000000000000\npassword=" + "PLACEHOLDER\n-----BEGIN RSA PRIVATE KEY-----")
	result := ins.InspectOutput(data)

	if result.Safe {
		t.Fatal("expected unsafe output")
	}
	if len(result.Concerns) < 3 {
		t.Errorf("expected at least 3 concerns, got %d: %v", len(result.Concerns), result.Concerns)
	}
}

func TestInspector_CaseInsensitive(t *testing.T) {
	ins := NewInspector()

	tests := []struct {
		name string
		data []byte
	}{
		{"uppercase PASSWORD", []byte("PASSWORD=" + "PLACEHOLDER_TEST")},
		{"lowercase password", []byte("password=" + "PLACEHOLDER_TEST")},
		{"mixed case Password", []byte("Password=" + "PLACEHOLDER_TEST")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			concerns := ins.InspectStdin(tt.data)
			if len(concerns) == 0 {
				t.Errorf("expected concerns for %q, got none", tt.data)
			}
		})
	}
}
