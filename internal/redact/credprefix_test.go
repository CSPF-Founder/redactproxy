package redact

// Vendor credential prefixes, kept as separate operands from the fixture
// bodies that follow them so that no assembled credential literal exists
// anywhere in this repository's source.
//
// Fixtures in this package must carry the exact byte shape of a real
// vendor credential, because that shape is what the detectors under test
// match on. Secret scanners match those same shapes against raw file
// bytes and cannot tell a fixture from a live key: GitHub push protection
// rejects the push outright, and a contributor running gitleaks or a
// pre-commit hook sees the whole tree as leaking. Splitting the prefix off
// keeps the assembled value out of the file while leaving it byte-identical
// at run time, since Go folds constant concatenation at compile time.
//
// Two kinds of fixture need nothing from this file: those already built
// with strings.Repeat or repeatStr, whose value never appears as a literal
// either, and a vendor's own published documentation placeholder
// (AKIAIOSFODNN7EXAMPLE and AWS's example secret key), which scanners
// allowlist.
const (
	anthropicPrefix            = "sk-ant-api03-"
	artifactoryPrefix          = "AKCp"
	awsKeyIDPrefix             = "AKIA"
	bitbucketPrefix            = "ATBB"
	circleCIPrefix             = "CCIPAT_"
	cloudflarePrefix           = "cfat_"
	digitalOceanPrefix         = "dop_v1_"
	dockerHubPrefix            = "dckr_pat_"
	githubPATPrefix            = "ghp_"
	gitlabPATPrefix            = "glpat-"
	googleAPIKeyPrefix         = "AIzaSy"
	npmPrefix                  = "npm_"
	openAIPrefix               = "sk-"
	openAIProjectPrefix        = "sk-proj-"
	razorpayLivePrefix         = "rzp_live_"
	sendGridPrefix             = "SG."
	slackBotPrefix             = "xoxb-"
	slackWebhookPrefix         = "hooks.slack.com/services/"
	stripeLivePrefix           = "sk_live_"
	stripeRestrictedTestPrefix = "rk_test_"
	stripeTestPrefix           = "sk_test_"
	terraformInfix             = ".atlasv1."
	twilioSIDPrefix            = "AC"
	vaultPrefix                = "hvs."
)
