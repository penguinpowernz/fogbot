package skills

import "testing"

func TestDeadman(t *testing.T) {
	var d Deadman
	if d.Pass("x") {
		t.Fatal("passing a condition that never failed is not a recovery")
	}
	if !d.Fail("x") {
		t.Fatal("first failure should report as started")
	}
	if d.Fail("x") {
		t.Fatal("repeat failure should not report as started")
	}
	if !d.Fail("y") {
		t.Fatal("conditions are tracked independently")
	}
	if !d.Pass("x") {
		t.Fatal("passing a failing condition should report recovery")
	}
	if d.Pass("x") {
		t.Fatal("repeat pass should not report recovery")
	}
}
