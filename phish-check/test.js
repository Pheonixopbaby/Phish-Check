const {
    levenshtein,
    isTyposquat,
    calculateScore
} = require('./analyzer.js');

const testCases = [
    { url: "https://google.com", expectedRisk: "low" },
    { url: "https://g00gle.com", expectedRisk: "high" },
    { url: "https://xn--80ak6aa92e.com", expectedRisk: "high" }, // Punycode
    { url: "http://192.168.1.1/login", expectedRisk: "high" },
    { url: "https://paypal-verify-account.xyz", expectedRisk: "high" },
    { url: "https://amazon.com/orders", expectedRisk: "low" },
    { url: "https://paypa1.com", expectedRisk: "high" },
    { url: "https://microsoft.com@secure-login.net", expectedRisk: "high" },
    { url: "https://a.b.c.d.e.f.google.com", expectedRisk: "medium" },
    { url: "https://netflix.com/verify", expectedRisk: "medium" },
];

function runTests() {
    console.log("--- Phish-Check Logic Tests ---\n");

    let passed = 0;

    testCases.forEach((tc, index) => {
        try {
            const url = new URL(tc.url);
            const flags = [];
            const domain = url.hostname;

            // Simple simulation of the analyzer logic
            if (domain.startsWith('xn--')) flags.push("punycode");
            if (domain.split('.').length > 4) flags.push("subdomains");
            if (url.pathname.includes('verify')) flags.push("keyword");
            if (isTyposquat(domain)) flags.push("typosquat");
            if (/^(\d{1,3}\.){3}\d{1,3}$/.test(domain)) flags.push("ip");
            if (tc.url.includes('@')) flags.push("user-info");

            const score = calculateScore(flags);

            let risk = "low";
            if (score > 70) risk = "high";
            else if (score > 30) risk = "medium";

            const success = risk === tc.expectedRisk;
            if (success) passed++;

            console.log(`Test ${index + 1}: ${tc.url}`);
            console.log(`  Score: ${score} | Risk: ${risk} | Expected: ${tc.expectedRisk}`);
            console.log(`  Result: ${success ? "✅ PASS" : "❌ FAIL"}\n`);
        } catch (e) {
            console.log(`Test ${index + 1}: ${tc.url} - ❌ ERROR: ${e.message}\n`);
        }
    });

    console.log(`--- Final Results: ${passed}/${testCases.length} passed ---`);
}

runTests();
