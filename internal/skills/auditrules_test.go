package skills

import "testing"

func TestAuditWatchListed(t *testing.T) {
	rules := "-w /etc/passwd -p rwa -k fb-file-500\n" +
		"-w /etc/cron.d -p wa -k fb-dir-540\n" +
		"-w /srv/my files -p wa -k fb-dir-540\n" +
		"-w /etc/shadow -p wa -k fb-file-5000\n" +
		"-a always,exit -F arch=b64 -S execve -k fb-file-500\n"

	for _, tc := range []struct {
		path, perms, key string
		want             bool
	}{
		{"/etc/passwd", "rwa", "fb-file-500", true},
		{"/etc/passwd", "war", "fb-file-500", true},  // listed in rwxa order
		{"/etc/cron.d/", "wa", "fb-dir-540", true},   // listed without the trailing slash
		{"/srv/my files", "wa", "fb-dir-540", true},  // spaces in the path
		{"/etc/passwd", "wa", "fb-file-500", false},  // different permissions
		{"/etc/shadow", "wa", "fb-file-500", false},  // only under a longer key
		{"/etc", "wa", "fb-dir-540", false},          // a prefix of a listed path
		{"/etc/passwd", "rwa", "fb-dir-540", false},  // another skill's key
		{"/etc/cron.d/x", "wa", "fb-dir-540", false}, // path not listed
	} {
		if got := AuditWatchListed(rules, tc.path, tc.perms, tc.key); got != tc.want {
			t.Errorf("AuditWatchListed(%q, %q, %q) = %v, want %v", tc.path, tc.perms, tc.key, got, tc.want)
		}
	}

	// auditctl itself may keep the trailing slash; that still matches
	if !AuditWatchListed("-w /etc/cron.d/ -p wa -k fb-dir-540", "/etc/cron.d", "wa", "fb-dir-540") {
		t.Error("listed path with a trailing slash didn't match")
	}
}

func TestAuditWatchesWithKey(t *testing.T) {
	rules := `-w /etc/passwd -p rwa -k fb-file-500
-w /etc/cron.d -p wa -k fb-dir-540
-w /root/my dir -p wa -k fb-dir-540
-w /etc/shadow -p rwa -k fb-file-5000
-a always,exit -F arch=b64 -S execve -k fb-dir-540`

	got := AuditWatchesWithKey(rules, "fb-dir-540")
	want := []AuditWatch{{"/etc/cron.d", "wa"}, {"/root/my dir", "wa"}}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
