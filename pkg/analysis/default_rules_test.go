package analysis

import (
	"k8s.io/apimachinery/pkg/util/sets"
	"strings"
	"testing"
	"time"

	"github.com/alcideio/rbac-tool/pkg/rbac"
	v1 "k8s.io/api/rbac/v1"
	"k8s.io/klog"
)

func subjectPoliciesForRules(rules ...v1.PolicyRule) []rbac.SubjectPolicyList {
	policyRules := make([]rbac.PolicyRule, 0, len(rules))
	for _, rule := range rules {
		policyRules = append(policyRules, rbac.PolicyRule{
			PolicyRule:     rule,
			OriginatedFrom: []v1.RoleRef{{Kind: "Role", Name: "test-role"}},
		})
	}

	return rbac.NewSubjectPermissionsList([]rbac.SubjectPermissions{
		{
			Subject: v1.Subject{
				Kind:      "ServiceAccount",
				Name:      "test-sa",
				Namespace: "test",
			},
			Rules: map[string][]rbac.PolicyRule{
				"test": policyRules,
			},
		},
	})
}

func findingRuleNames(report *AnalysisReport) map[string]bool {
	matched := map[string]bool{}
	for _, finding := range report.Findings {
		matched[finding.Finding.RuleName] = true
	}
	return matched
}

func Test__DefultRulesUUIDs(t *testing.T) {
	uids := sets.NewString()
	config := DefaultAnalysisConfig()
	for i, rule := range config.Rules {
		if uids.Has(strings.ToLower(rule.Uuid)) {
			t.Fatalf("Rule '%v' - %v - duplicate UUID", i, rule.Name)
			t.Fail()
		}
		uids.Insert(strings.ToLower(rule.Uuid))
	}
}

func Test__VerifyDefultRules(t *testing.T) {

	config := DefaultAnalysisConfig()

	for i, rule := range config.Rules {
		if r, err := newAnalysisRule(&config.Rules[i]); err != nil || r == nil {
			t.Fatalf("Rule '%v' - %v - failed to initialize\n%v\n", i, rule.Name, err)
			t.Fail()
		}
	}
}

func Test__Analyzer(t *testing.T) {
	defer klog.Flush()

	config := DefaultAnalysisConfig()

	analyzer := CreateAnalyzer(
		config,
		[]rbac.SubjectPolicyList{
			{Subject: v1.Subject{
				Kind:      "ServiceAccount",
				APIGroup:  "",
				Name:      "test-sa",
				Namespace: "test",
			}, AllowedTo: []rbac.NamespacedPolicyRule{
				{Namespace: "test", Verb: "get", APIGroup: "*", Resource: "*", ResourceNames: nil, NonResourceURLs: nil},
			}},
		},
	)

	if analyzer == nil {
		t.Fail()
	}

	report, err := analyzer.Analyze()
	if err != nil {
		t.Fatalf("Analysis failed - %v", err)
		t.Fail()
	}

	if len(report.Findings) == 0 {
		t.Fatalf("Expecting findings")
		t.Fail()
	}

	//t.Logf("%v", pretty.Sprint(report))
}

func Test__GlobalExclusion(t *testing.T) {
	defer klog.Flush()

	config := DefaultAnalysisConfig()

	analyzer := CreateAnalyzer(
		config,
		[]rbac.SubjectPolicyList{
			{Subject: v1.Subject{
				Kind:      "ServiceAccount",
				APIGroup:  "",
				Name:      "test-sa",
				Namespace: "kube-system",
			}, AllowedTo: []rbac.NamespacedPolicyRule{
				{Namespace: "test", Verb: "get", APIGroup: "*", Resource: "*", ResourceNames: nil, NonResourceURLs: nil},
			}},
		},
	)

	if analyzer == nil {
		t.Fail()
	}

	report, err := analyzer.Analyze()
	if err != nil {
		t.Fatalf("Analysis failed - %v", err)
		t.Fail()
	}

	if len(report.Findings) != 0 {
		t.Fatalf("Expecting no findings")
		t.Fail()
	}

	//t.Logf("%v", pretty.Sprint(report))
}

func Test__RuleExclusion(t *testing.T) {
	defer klog.Flush()

	config := DefaultAnalysisConfig()

	config.Rules = config.Rules[0:1]

	config.Rules[0].Exclusions = []Exclusion{
		{
			Disabled:     false,
			Comment:      "Exclude test from analysis",
			AddedBy:      "tester",
			LastModified: time.Now().Format(time.RFC3339),
			ValidBefore:  0,
			Expression:   `subject.namespace == "test"`,
		},
	}

	analyzer := CreateAnalyzer(
		config,
		[]rbac.SubjectPolicyList{
			{Subject: v1.Subject{
				Kind:      "ServiceAccount",
				APIGroup:  "",
				Name:      "test-sa",
				Namespace: "test",
			}, AllowedTo: []rbac.NamespacedPolicyRule{
				{Namespace: "test", Verb: "get", APIGroup: "*", Resource: "*", ResourceNames: nil, NonResourceURLs: nil},
			}},
		},
	)

	if analyzer == nil {
		t.Fail()
	}

	report, err := analyzer.Analyze()
	if err != nil {
		t.Fatalf("Analysis failed - %v", err)
		t.Fail()
	}

	if len(report.Findings) != 0 {
		t.Fatalf("Expecting no findings")
		t.Fail()
	}

	//t.Logf("%v", pretty.Sprint(report))
}

func Test__EmptySubjectPolicyList(t *testing.T) {
	defer klog.Flush()

	config := DefaultAnalysisConfig()

	analyzer := CreateAnalyzer(
		config,
		[]rbac.SubjectPolicyList{
			{Subject: v1.Subject{
				Kind:      "ServiceAccount",
				APIGroup:  "",
				Name:      "test-sa",
				Namespace: "test",
			},
				AllowedTo: []rbac.NamespacedPolicyRule{},
			},
		},
	)

	if analyzer == nil {
		t.Fail()
	}

	report, err := analyzer.Analyze()
	if err != nil {
		t.Fatalf("Analysis failed - %v", err)
		t.Fail()
	}

	if len(report.Findings) != 0 {
		t.Fatalf("Expecting no findings")
		t.Fail()
	}

	//t.Logf("%v", pretty.Sprint(report))
}

func Test__CoreAPIGroupHighRiskRules(t *testing.T) {
	defer klog.Flush()

	config := DefaultAnalysisConfig()

	analyzer := CreateAnalyzer(
		config,
		subjectPoliciesForRules(
			v1.PolicyRule{
				Verbs:     []string{"create"},
				APIGroups: []string{""},
				Resources: []string{"nodes/proxy"},
			},
			v1.PolicyRule{
				Verbs:     []string{"create"},
				APIGroups: []string{""},
				Resources: []string{"pods/exec"},
			},
			v1.PolicyRule{
				Verbs:     []string{"update"},
				APIGroups: []string{""},
				Resources: []string{"pods/ephemeralcontainers"},
			},
		),
	)

	if analyzer == nil {
		t.Fail()
	}

	report, err := analyzer.Analyze()
	if err != nil {
		t.Fatalf("Analysis failed - %v", err)
	}

	matched := findingRuleNames(report)

	for _, ruleName := range []string{
		"Create Node Proxy",
		"Exec into Pod",
		"Create Ephemeral Containers in Running Pods",
	} {
		if !matched[ruleName] {
			t.Fatalf("Expecting a finding for rule '%v', got findings %+v", ruleName, report.Findings)
		}
	}
}

func Test__ResourceNamesUnrestricted(t *testing.T) {
	defer klog.Flush()

	config := DefaultAnalysisConfig()

	analyzer := CreateAnalyzer(
		config,
		subjectPoliciesForRules(v1.PolicyRule{
			Verbs:     []string{"get"},
			APIGroups: []string{""},
			Resources: []string{"secrets"},
		}),
	)

	if analyzer == nil {
		t.Fail()
	}

	report, err := analyzer.Analyze()
	if err != nil {
		t.Fatalf("Analysis failed - %v", err)
	}

	if !findingRuleNames(report)["Secret Readers"] {
		t.Fatalf("Expecting a 'Secret Readers' finding for unrestricted secrets access, got %+v", report.Findings)
	}
}

func Test__ResourceNamesRestricted(t *testing.T) {
	defer klog.Flush()

	config := DefaultAnalysisConfig()

	analyzer := CreateAnalyzer(
		config,
		subjectPoliciesForRules(v1.PolicyRule{
			Verbs:         []string{"get"},
			APIGroups:     []string{""},
			Resources:     []string{"secrets"},
			ResourceNames: []string{"my-secret"},
		}),
	)

	if analyzer == nil {
		t.Fail()
	}

	report, err := analyzer.Analyze()
	if err != nil {
		t.Fatalf("Analysis failed - %v", err)
	}

	if findingRuleNames(report)["Secret Readers"] {
		t.Fatalf("Expecting no 'Secret Readers' finding for resourceNames-restricted secrets access, got %+v", report.Findings)
	}
}
