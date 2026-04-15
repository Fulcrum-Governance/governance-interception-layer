package cli

import (
	"testing"

	"github.com/fulcrum-governance/gil/governance"
)

func TestParseCommand(t *testing.T) {
	tests := []struct {
		name    string
		cmd     string
		want    []governance.PipeSegment
		wantErr bool
	}{
		{
			name: "simple command",
			cmd:  "ls -la",
			want: []governance.PipeSegment{
				{Command: "ls", Args: []string{"-la"}},
			},
		},
		{
			name: "single command no args",
			cmd:  "pwd",
			want: []governance.PipeSegment{
				{Command: "pwd", Args: nil},
			},
		},
		{
			name: "two-stage pipe",
			cmd:  "cat /etc/passwd | grep root",
			want: []governance.PipeSegment{
				{Command: "cat", Args: []string{"/etc/passwd"}},
				{Command: "grep", Args: []string{"root"}},
			},
		},
		{
			name: "three-stage pipe",
			cmd:  "ps aux | grep nginx | wc -l",
			want: []governance.PipeSegment{
				{Command: "ps", Args: []string{"aux"}},
				{Command: "grep", Args: []string{"nginx"}},
				{Command: "wc", Args: []string{"-l"}},
			},
		},
		{
			name: "command with double-quoted string",
			cmd:  `echo "hello world" | wc -w`,
			want: []governance.PipeSegment{
				{Command: "echo", Args: []string{"hello world"}},
				{Command: "wc", Args: []string{"-w"}},
			},
		},
		{
			name: "command with single-quoted string",
			cmd:  `grep 'error|warn' /var/log/syslog`,
			want: []governance.PipeSegment{
				{Command: "grep", Args: []string{"error|warn", "/var/log/syslog"}},
			},
		},
		{
			name: "pipe inside quotes is not split",
			cmd:  `echo "a | b" | cat`,
			want: []governance.PipeSegment{
				{Command: "echo", Args: []string{"a | b"}},
				{Command: "cat", Args: nil},
			},
		},
		{
			name: "escaped double quote inside double quotes",
			cmd:  `echo "say \"hello\"" | cat`,
			want: []governance.PipeSegment{
				{Command: "echo", Args: []string{`say "hello"`}},
				{Command: "cat", Args: nil},
			},
		},
		{
			name: "escaped single quote inside single quotes",
			cmd:  `echo 'it'\''s fine'`,
			// This is actually two adjacent single-quoted tokens that get concatenated
			// in bash, but our tokenizer treats them as separate because the quote toggles.
			// Let's adjust: 'it' + \' + 's fine' — actually this is a bash-ism.
			// Our parser: 'it' ends the quote, then ' starts a new one, s fine' => unbalanced
			// Let's use the simpler escaped form instead.
			wantErr: true, // unbalanced quotes — the bash idiom 'it'\''s' isn't simple quoting
		},
		{
			name: "multiple spaces between args",
			cmd:  "ls   -la   /tmp",
			want: []governance.PipeSegment{
				{Command: "ls", Args: []string{"-la", "/tmp"}},
			},
		},
		{
			name: "tabs as whitespace",
			cmd:  "ls\t-la\t/tmp",
			want: []governance.PipeSegment{
				{Command: "ls", Args: []string{"-la", "/tmp"}},
			},
		},
		{
			name: "leading and trailing whitespace",
			cmd:  "  ls -la  ",
			want: []governance.PipeSegment{
				{Command: "ls", Args: []string{"-la"}},
			},
		},
		{
			name: "pipe with spaces around it",
			cmd:  "cat file.txt  |  sort  |  uniq -c",
			want: []governance.PipeSegment{
				{Command: "cat", Args: []string{"file.txt"}},
				{Command: "sort", Args: nil},
				{Command: "uniq", Args: []string{"-c"}},
			},
		},
		{
			name:    "empty command",
			cmd:     "",
			wantErr: true,
		},
		{
			name:    "whitespace only",
			cmd:     "   ",
			wantErr: true,
		},
		{
			name:    "unbalanced double quotes",
			cmd:     `echo "hello`,
			wantErr: true,
		},
		{
			name:    "unbalanced single quotes",
			cmd:     `echo 'hello`,
			wantErr: true,
		},
		{
			name:    "empty pipe segment",
			cmd:     "ls | | cat",
			wantErr: true,
		},
		{
			name:    "trailing pipe",
			cmd:     "ls |",
			wantErr: true,
		},
		{
			name:    "leading pipe",
			cmd:     "| ls",
			wantErr: true,
		},
		{
			name: "complex command with multiple args",
			cmd:  "find /var/log -name '*.log' -mtime +7 | xargs rm",
			want: []governance.PipeSegment{
				{Command: "find", Args: []string{"/var/log", "-name", "*.log", "-mtime", "+7"}},
				{Command: "xargs", Args: []string{"rm"}},
			},
		},
		{
			name: "command with equals in arg",
			cmd:  "env VAR=value printenv",
			want: []governance.PipeSegment{
				{Command: "env", Args: []string{"VAR=value", "printenv"}},
			},
		},
		{
			name: "mixed quotes",
			cmd:  `grep "pattern" 'file.txt' | wc -l`,
			want: []governance.PipeSegment{
				{Command: "grep", Args: []string{"pattern", "file.txt"}},
				{Command: "wc", Args: []string{"-l"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCommand(tt.cmd)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseCommand(%q) expected error, got nil", tt.cmd)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseCommand(%q) unexpected error: %v", tt.cmd, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("ParseCommand(%q) returned %d segments, want %d", tt.cmd, len(got), len(tt.want))
			}
			for i := range got {
				if got[i].Command != tt.want[i].Command {
					t.Errorf("segment[%d].Command = %q, want %q", i, got[i].Command, tt.want[i].Command)
				}
				if len(got[i].Args) != len(tt.want[i].Args) {
					t.Errorf("segment[%d].Args length = %d, want %d (got %v, want %v)",
						i, len(got[i].Args), len(tt.want[i].Args), got[i].Args, tt.want[i].Args)
					continue
				}
				for j := range got[i].Args {
					if got[i].Args[j] != tt.want[i].Args[j] {
						t.Errorf("segment[%d].Args[%d] = %q, want %q", i, j, got[i].Args[j], tt.want[i].Args[j])
					}
				}
			}
		})
	}
}
