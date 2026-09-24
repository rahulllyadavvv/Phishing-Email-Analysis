/*
 * Example rule shipped with PhishLens. It matches a harmless marker string used by the tests,
 * so YARA scanning can be verified without real malware. Add your own rules next to it.
 */
rule PhishLens_Test_Marker
{
    meta:
        description = "Harmless PhishLens test marker (used by the test suite)"
        severity = "medium"
        author = "PhishLens"
    strings:
        $marker = "PHISHLENS-YARA-TEST-MARKER"
    condition:
        $marker
}
