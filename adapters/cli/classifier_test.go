package cli

import (
	"testing"
)

func TestClassifier_BuiltinCommands(t *testing.T) {
	c := NewClassifier()

	tests := []struct {
		name string
		cmd  string
		want string
	}{
		// read commands
		{"ls is read", "ls", RiskRead},
		{"cat is read", "cat", RiskRead},
		{"head is read", "head", RiskRead},
		{"tail is read", "tail", RiskRead},
		{"grep is read", "grep", RiskRead},
		{"find is read", "find", RiskRead},
		{"jq is read", "jq", RiskRead},
		{"wc is read", "wc", RiskRead},
		{"echo is read", "echo", RiskRead},
		{"env is read", "env", RiskRead},
		{"pwd is read", "pwd", RiskRead},
		{"whoami is read", "whoami", RiskRead},
		{"date is read", "date", RiskRead},
		{"uname is read", "uname", RiskRead},
		{"ps is read", "ps", RiskRead},
		{"df is read", "df", RiskRead},
		{"du is read", "du", RiskRead},
		{"file is read", "file", RiskRead},
		{"which is read", "which", RiskRead},
		{"type is read", "type", RiskRead},
		{"less is read", "less", RiskRead},
		{"more is read", "more", RiskRead},
		{"sort is read", "sort", RiskRead},
		{"uniq is read", "uniq", RiskRead},
		{"cut is read", "cut", RiskRead},
		{"awk is read", "awk", RiskRead},
		{"sed is read", "sed", RiskRead},
		{"tr is read", "tr", RiskRead},
		{"diff is read", "diff", RiskRead},
		{"comm is read", "comm", RiskRead},
		{"stat is read", "stat", RiskRead},
		{"id is read", "id", RiskRead},
		{"hostname is read", "hostname", RiskRead},
		{"dig is read", "dig", RiskRead},
		{"nslookup is read", "nslookup", RiskRead},
		{"ping is read", "ping", RiskRead},

		// write commands
		{"curl is write", "curl", RiskWrite},
		{"wget is write", "wget", RiskWrite},
		{"cp is write", "cp", RiskWrite},
		{"mv is write", "mv", RiskWrite},
		{"mkdir is write", "mkdir", RiskWrite},
		{"touch is write", "touch", RiskWrite},
		{"tee is write", "tee", RiskWrite},
		{"tar is write", "tar", RiskWrite},
		{"zip is write", "zip", RiskWrite},
		{"unzip is write", "unzip", RiskWrite},
		{"gzip is write", "gzip", RiskWrite},
		{"gunzip is write", "gunzip", RiskWrite},
		{"ln is write", "ln", RiskWrite},
		{"install is write", "install", RiskWrite},
		{"git is write", "git", RiskWrite},
		{"npm is write", "npm", RiskWrite},
		{"pip is write", "pip", RiskWrite},

		// admin commands
		{"chmod is admin", "chmod", RiskAdmin},
		{"chown is admin", "chown", RiskAdmin},
		{"chgrp is admin", "chgrp", RiskAdmin},
		{"systemctl is admin", "systemctl", RiskAdmin},
		{"service is admin", "service", RiskAdmin},
		{"docker is admin", "docker", RiskAdmin},
		{"kubectl is admin", "kubectl", RiskAdmin},
		{"helm is admin", "helm", RiskAdmin},
		{"mount is admin", "mount", RiskAdmin},
		{"umount is admin", "umount", RiskAdmin},
		{"useradd is admin", "useradd", RiskAdmin},
		{"userdel is admin", "userdel", RiskAdmin},
		{"groupadd is admin", "groupadd", RiskAdmin},
		{"iptables is admin", "iptables", RiskAdmin},
		{"ufw is admin", "ufw", RiskAdmin},
		{"crontab is admin", "crontab", RiskAdmin},
		{"ssh is admin", "ssh", RiskAdmin},
		{"scp is admin", "scp", RiskAdmin},
		{"rsync is admin", "rsync", RiskAdmin},

		// destructive commands
		{"rm is destructive", "rm", RiskDestructive},
		{"rmdir is destructive", "rmdir", RiskDestructive},
		{"dd is destructive", "dd", RiskDestructive},
		{"mkfs is destructive", "mkfs", RiskDestructive},
		{"fdisk is destructive", "fdisk", RiskDestructive},
		{"DROP is destructive", "DROP", RiskDestructive},
		{"TRUNCATE is destructive", "TRUNCATE", RiskDestructive},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := c.ClassifyCommand(tt.cmd)
			if got != tt.want {
				t.Errorf("ClassifyCommand(%q) = %q, want %q", tt.cmd, got, tt.want)
			}
		})
	}
}

func TestClassifier_UnknownCommand(t *testing.T) {
	c := NewClassifier()
	got := c.ClassifyCommand("unknown-tool-xyz")
	if got != RiskAdmin {
		t.Errorf("ClassifyCommand(unknown) = %q, want %q", got, RiskAdmin)
	}
}

func TestClassifier_CustomDefaultRisk(t *testing.T) {
	c := NewClassifier()
	c.DefaultRisk = RiskDestructive
	got := c.ClassifyCommand("unknown-tool-xyz")
	if got != RiskDestructive {
		t.Errorf("ClassifyCommand(unknown) with custom default = %q, want %q", got, RiskDestructive)
	}
}

func TestClassifier_Overrides(t *testing.T) {
	tests := []struct {
		name     string
		cmd      string
		override string
		want     string
	}{
		{
			name:     "override read to write",
			cmd:      "cat",
			override: RiskWrite,
			want:     RiskWrite,
		},
		{
			name:     "override rm to read (tenant trusts it)",
			cmd:      "rm",
			override: RiskRead,
			want:     RiskRead,
		},
		{
			name:     "override unknown to read",
			cmd:      "custom-script",
			override: RiskRead,
			want:     RiskRead,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClassifier()
			c.Overrides[tt.cmd] = tt.override
			got := c.ClassifyCommand(tt.cmd)
			if got != tt.want {
				t.Errorf("ClassifyCommand(%q) with override = %q, want %q", tt.cmd, got, tt.want)
			}
		})
	}
}

func TestClassifier_OverrideTakesPrecedence(t *testing.T) {
	c := NewClassifier()
	// rm is normally destructive
	if got := c.ClassifyCommand("rm"); got != RiskDestructive {
		t.Fatalf("baseline: rm = %q, want destructive", got)
	}
	// Override to write
	c.Overrides["rm"] = RiskWrite
	if got := c.ClassifyCommand("rm"); got != RiskWrite {
		t.Errorf("overridden: rm = %q, want write", got)
	}
}

func TestClassifier_EmptyDefaultFallback(t *testing.T) {
	c := &Classifier{
		Overrides:   make(map[string]string),
		DefaultRisk: "",
	}
	got := c.ClassifyCommand("unknown-tool")
	if got != RiskAdmin {
		t.Errorf("ClassifyCommand with empty default = %q, want %q", got, RiskAdmin)
	}
}
