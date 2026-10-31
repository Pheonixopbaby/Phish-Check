/**
 * Phish-Check Analysis Logic
 */

const POPULAR_BRANDS = [
    "google", "facebook", "amazon", "apple", "microsoft",
    "netflix", "paypal", "twitter", "instagram", "chase"
    // Add more brands up to ~30
];

/**
 * Calculates the Levenshtein distance between two strings.
 * This is used to detect typosquatting (e.g., "g00gle" vs "google").
 *
 * @param {string} a
 * @param {string} b
 * @returns {number} The edit distance
 *
 * Example: levenshtein("apple", "applee") -> 1
 * Hint: Look up the dynamic programming approach using a 2D array or two rows.
 */
function levenshtein(a, b) {
    const matrix = [];

    for (let i = 0; i <= b.length; i++) {
        matrix[i] = [i];
    }
    for (let j = 0; j <= a.length; j++) {
        matrix[0][j] = j;
    }

    for (let i = 1; i <= b.length; i++) {
        for (let j = 1; j <= a.length; j++) {
            const cost = a[j - 1] === b[i - 1] ? 0 : 1;
            matrix[i][j] = Math.min(
                matrix[i - 1][j] + 1,
                matrix[i][j - 1] + 1,
                matrix[i - 1][j - 1] + cost
            );
        }
    }
    return matrix[b.length][a.length];
}

/**
 * Checks if a domain is a typosquat of any popular brand.
 *
 * @param {string} domain
 * @returns {boolean} True if it looks like a typosquat
 */
function isTyposquat(domain) {
    // 1. Get the main part of the domain (before the first dot)
    const mainPart = domain.split('.')[0].toLowerCase();

    // 2. Check it against every popular brand
    return POPULAR_BRANDS.some(brand => {
        const distance = levenshtein(mainPart, brand);
        // If distance is 1 or 2, it's likely a typo (e.g., "goog1e" vs "google")
        // But we don't mark it if the words are exactly the same (distance 0)
        return distance > 0 && distance <= 2;
    });
}

/**
 * Calculates a risk score based on a list of found red flags.
 *
 * @param {string[]} flags
 * @returns {number} Score from 0 to 100
 *
 * Example: calculateScore(["punycode", "ip-host"]) -> 70
 * Hint: Assign different weights to different flags (e.g., punycode is more suspicious than 'login' in path).
 */
function calculateScore(flags) {
    let score = 0;

    flags.forEach(flag => {
        if (flag.includes("Punycode")) score += 50;
        else if (flag.includes("IP address")) score += 40;
        else if (flag.includes("user-info")) score += 30;
        else if (flag.includes("typosquatting")) score += 40;
        else if (flag.includes("TLD")) score += 20;
        else if (flag.includes("shortener")) score += 15;
        else if (flag.includes("subdomains")) score += 15;
        else if (flag.includes("keywords")) score += 20;
    });

    return Math.min(score, 100);
}

function analyzeURL() {
    const urlInput = document.getElementById('urlInput').value;
    if (!urlInput) return;

    try {
        const url = new URL(urlInput);
        const flags = [];
        const domain = url.hostname;

        // 1. Punycode/IDN Lookalikes
        if (domain.startsWith('xn--')) {
            flags.push("Punycode/IDN lookalike detected (xn--)");
        }

        // 2. Mixed-script domains (simplified check for non-ASCII)
        if (/[^\x00-\x7F]/.test(domain)) {
            flags.push("Mixed-script or non-ASCII characters in domain");
        }

        // 3. Suspicious TLDs (example list)
        const suspiciousTLDs = ['.xyz', '.top', '.buzz', '.gdn', '.loan'];
        if (suspiciousTLDs.some(tld => domain.endsWith(tld))) {
            flags.push("Suspicious top-level domain (TLD)");
        }

        // 4. URL Shorteners
        const shorteners = ['bit.ly', 't.co', 'goo.gl', 'tinyurl.com'];
        if (shorteners.some(s => domain.includes(s))) {
            flags.push("URL shortener detected");
        }

        // 5. '@' in URL (User-info subversion)
        if (urlInput.includes('@')) {
            flags.push("User-info '@' symbol detected in URL");
        }

        // 6. IP-address hosts
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (ipRegex.test(domain)) {
            flags.push("Domain is a raw IP address");
        }

        // 7. Excessive subdomains
        if (domain.split('.').length > 4) {
            flags.push("Excessive number of subdomains");
        }

        // 8. Typosquatting (Your TODO)
        if (isTyposquat(domain)) {
            flags.push("Potential typosquatting of a popular brand");
        }

        // 9. 'login' / 'verify' keywords in path
        if (url.pathname.toLowerCase().includes('login') || url.pathname.toLowerCase().includes('verify')) {
            flags.push("Suspicious keywords ('login'/'verify') in path");
        }

        const score = calculateScore(flags);
        displayResults(score, flags);

    } catch (e) {
        alert("Please enter a valid URL (including http:// or https://)");
    }
}

function displayResults(score, flags) {
    const resultDiv = document.getElementById('result');
    const scoreDisplay = document.getElementById('scoreDisplay');
    const reasonsList = document.getElementById('reasonsList');

    resultDiv.style.display = 'block';
    scoreDisplay.innerText = `Risk Score: ${score}/100`;

    // Color the score
    if (score < 30) scoreDisplay.style.color = 'var(--success)';
    else if (score < 70) scoreDisplay.style.color = 'orange';
    else scoreDisplay.style.color = 'var(--danger)';

    reasonsList.innerHTML = flags.map(f => `<li>${f}</li>`).join('');
}

// Export for node testing
if (typeof module !== 'undefined') {
    module.exports = {
        analyzeURL,
        levenshtein,
        isTyposquat,
        calculateScore,
        POPULAR_BRANDS
    };
}
