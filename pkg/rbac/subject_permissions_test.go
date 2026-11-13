package rbac

import (
	"testing"

	v1 "k8s.io/api/rbac/v1"
)

func subjectPermissionsFixture(rules ...v1.PolicyRule) []SubjectPermissions {
	policyRules := make([]PolicyRule, 0, len(rules))
	for _, rule := range rules {
		policyRules = append(policyRules, PolicyRule{
			PolicyRule:     rule,
			OriginatedFrom: []v1.RoleRef{{Kind: "Role", Name: "test-role"}},
		})
	}

	return []SubjectPermissions{
		{
			Subject: v1.Subject{
				Kind:      v1.ServiceAccountKind,
				Name:      "test-sa",
				Namespace: "test",
			},
			Rules: map[string][]PolicyRule{
				"test": policyRules,
			},
		},
	}
}

func Test__NewSubjectPermissionsListNormalization(t *testing.T) {
	policies := NewSubjectPermissionsList(subjectPermissionsFixture(v1.PolicyRule{
		Verbs:     []string{"get"},
		APIGroups: []string{""},
		Resources: []string{"secrets"},
	}))

	if len(policies) != 1 || len(policies[0].AllowedTo) != 1 {
		t.Fatalf("Expecting a single flattened rule, got %+v", policies)
	}

	rule := policies[0].AllowedTo[0]

	if rule.APIGroup != "core" {
		t.Fatalf("Expecting empty apiGroup to be normalized to 'core', got '%v'", rule.APIGroup)
	}

	if len(rule.ResourceNames) != 1 || rule.ResourceNames[0] != "*" {
		t.Fatalf("Expecting empty resourceNames to be normalized to ['*'], got %v", rule.ResourceNames)
	}

	if len(rule.OriginatedFrom) != 1 || rule.OriginatedFrom[0].Name != "test-role" {
		t.Fatalf("Expecting OriginatedFrom to be preserved, got %+v", rule.OriginatedFrom)
	}
}

func Test__NewSubjectPermissionsListWildcardNormalization(t *testing.T) {
	policies := NewSubjectPermissionsList(subjectPermissionsFixture(v1.PolicyRule{
		Verbs:     []string{""},
		APIGroups: []string{"apps"},
		Resources: []string{""},
	}))

	if len(policies) != 1 || len(policies[0].AllowedTo) != 1 {
		t.Fatalf("Expecting a single flattened rule, got %+v", policies)
	}

	rule := policies[0].AllowedTo[0]

	if rule.Verb != "*" {
		t.Fatalf("Expecting empty verb to be normalized to '*', got '%v'", rule.Verb)
	}

	if rule.Resource != "*" {
		t.Fatalf("Expecting empty resource to be normalized to '*', got '%v'", rule.Resource)
	}
}

func Test__NewSubjectPermissionsListResourceNamesRestricted(t *testing.T) {
	policies := NewSubjectPermissionsList(subjectPermissionsFixture(v1.PolicyRule{
		Verbs:         []string{"get"},
		APIGroups:     []string{""},
		Resources:     []string{"secrets"},
		ResourceNames: []string{"my-secret"},
	}))

	if len(policies) != 1 || len(policies[0].AllowedTo) != 1 {
		t.Fatalf("Expecting a single flattened rule, got %+v", policies)
	}

	rule := policies[0].AllowedTo[0]

	if len(rule.ResourceNames) != 1 || rule.ResourceNames[0] != "my-secret" {
		t.Fatalf("Expecting resourceNames restriction to be preserved, got %v", rule.ResourceNames)
	}
}

func Test__NormalizeResourceNames(t *testing.T) {
	if got := NormalizeResourceNames(nil); len(got) != 1 || got[0] != "*" {
		t.Fatalf("Expecting nil resourceNames to be normalized to ['*'], got %v", got)
	}

	if got := NormalizeResourceNames([]string{}); len(got) != 1 || got[0] != "*" {
		t.Fatalf("Expecting empty resourceNames to be normalized to ['*'], got %v", got)
	}

	if got := NormalizeResourceNames([]string{""}); len(got) != 1 || got[0] != "*" {
		t.Fatalf("Expecting empty-string resourceNames to be normalized to ['*'], got %v", got)
	}

	if got := NormalizeResourceNames([]string{"a", "b"}); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("Expecting explicit resourceNames to be preserved, got %v", got)
	}
}
