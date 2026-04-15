package cli

// RiskLevel constants for command classification.
const (
	RiskRead        = "read"
	RiskWrite       = "write"
	RiskAdmin       = "admin"
	RiskDestructive = "destructive"
)

// Classifier maps shell commands to risk levels. It uses a built-in
// static table of ~50 common commands and supports per-tenant overrides.
// Unknown commands default to "admin" (conservative).
type Classifier struct {
	// Overrides allows per-tenant risk level customization.
	// Keys are command names, values are risk levels.
	Overrides map[string]string

	// DefaultRisk is returned for commands not in the static map
	// or overrides. Defaults to "admin" if empty.
	DefaultRisk string
}

// NewClassifier creates a Classifier with sensible defaults.
func NewClassifier() *Classifier {
	return &Classifier{
		Overrides:   make(map[string]string),
		DefaultRisk: RiskAdmin,
	}
}

// ClassifyCommand returns the risk level for the given command name.
// Overrides take precedence over the built-in map.
func (c *Classifier) ClassifyCommand(cmd string) string {
	if level, ok := c.Overrides[cmd]; ok {
		return level
	}
	if level, ok := builtinRiskMap[cmd]; ok {
		return level
	}
	if c.DefaultRisk != "" {
		return c.DefaultRisk
	}
	return RiskAdmin
}

// builtinRiskMap is the static classification table for common commands.
var builtinRiskMap = map[string]string{
	// read — information gathering, no side effects
	"ls":       RiskRead,
	"cat":      RiskRead,
	"head":     RiskRead,
	"tail":     RiskRead,
	"grep":     RiskRead,
	"find":     RiskRead,
	"jq":       RiskRead,
	"wc":       RiskRead,
	"echo":     RiskRead,
	"env":      RiskRead,
	"pwd":      RiskRead,
	"whoami":   RiskRead,
	"date":     RiskRead,
	"uname":    RiskRead,
	"ps":       RiskRead,
	"df":       RiskRead,
	"du":       RiskRead,
	"file":     RiskRead,
	"which":    RiskRead,
	"type":     RiskRead,
	"less":     RiskRead,
	"more":     RiskRead,
	"sort":     RiskRead,
	"uniq":     RiskRead,
	"cut":      RiskRead,
	"awk":      RiskRead,
	"sed":      RiskRead,
	"tr":       RiskRead,
	"diff":     RiskRead,
	"comm":     RiskRead,
	"stat":     RiskRead,
	"id":       RiskRead,
	"hostname": RiskRead,
	"dig":      RiskRead,
	"nslookup": RiskRead,
	"ping":     RiskRead,
	"curl":     RiskWrite, // can't reliably distinguish GET vs POST
	"wget":     RiskWrite,

	// write — modifies files but reversible
	"cp":      RiskWrite,
	"mv":      RiskWrite,
	"mkdir":   RiskWrite,
	"touch":   RiskWrite,
	"tee":     RiskWrite,
	"tar":     RiskWrite,
	"zip":     RiskWrite,
	"unzip":   RiskWrite,
	"gzip":    RiskWrite,
	"gunzip":  RiskWrite,
	"ln":      RiskWrite,
	"install": RiskWrite,
	"git":     RiskWrite,
	"npm":     RiskWrite,
	"pip":     RiskWrite,

	// admin — system-level operations
	"chmod":     RiskAdmin,
	"chown":     RiskAdmin,
	"chgrp":     RiskAdmin,
	"systemctl": RiskAdmin,
	"service":   RiskAdmin,
	"docker":    RiskAdmin,
	"kubectl":   RiskAdmin,
	"helm":      RiskAdmin,
	"mount":     RiskAdmin,
	"umount":    RiskAdmin,
	"useradd":   RiskAdmin,
	"userdel":   RiskAdmin,
	"groupadd":  RiskAdmin,
	"iptables":  RiskAdmin,
	"ufw":       RiskAdmin,
	"crontab":   RiskAdmin,
	"ssh":       RiskAdmin,
	"scp":       RiskAdmin,
	"rsync":     RiskAdmin,

	// destructive — irreversible data loss
	"rm":       RiskDestructive,
	"rmdir":    RiskDestructive,
	"dd":       RiskDestructive,
	"mkfs":     RiskDestructive,
	"fdisk":    RiskDestructive,
	"DROP":     RiskDestructive,
	"TRUNCATE": RiskDestructive,
}
