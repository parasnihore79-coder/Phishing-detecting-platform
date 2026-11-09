document.addEventListener("DOMContentLoaded", function() {
    function $(selector) {
        return document.querySelector(selector);
    }
    
    var toast = $("#toast");

    function showToast(message) {
        if (!toast) return alert(message);
        toast.textContent = message;
        toast.classList.add("show");
        setTimeout(function() {
            toast.classList.remove("show");
        }, 3000);
    }

    function escapeHTML(str) {
        return String(str || "").replace(/[&<>"']/g, function(c) {
            return {
                "&": "&amp;",
                "<": "&lt;",
                ">": "&gt;",
                '"': "&quot;",
                "'": "&#039;"
            }[c];
        });
    }

    function sendRequest(url, data) {
        var options = {
            method: data ? "POST" : "GET",
            headers: { "Content-Type": "application/json" }
        };
        if (data) options.body = JSON.stringify(data);
        
        return fetch(url, options).then(function(res) {
            return res.json().then(function(result) {
                if (!res.ok || !result.success) {
                    throw new Error(result.error || "Request failed.");
                }
                return result;
            });
        });
    }

    function setLoading(btn, loading) {
        if (!btn) return;
        if (loading) {
            btn.dataset.oldText = btn.textContent;
            btn.textContent = "Scanning...";
            btn.disabled = true;
        } else {
            btn.textContent = btn.dataset.oldText || "Submit";
            btn.disabled = false;
        }
    }

    function getBadgeClass(val) {
        var t = String(val || "").toLowerCase();
        if (t.indexOf("low") !== -1 || t.indexOf("valid") !== -1 || t.indexOf("optimal") !== -1 || t.indexOf("verified") !== -1 || t.indexOf("clean") !== -1) {
            return "badge-success";
        }
        if (t.indexOf("suspicious") !== -1 || t.indexOf("warning") !== -1 || t.indexOf("expiring") !== -1) {
            return "badge-warning";
        }
        return "badge-danger";
    }

    function findingHTML(item) {
        return '<div class="finding ' + (item.info || 'info') + '" style="margin-bottom:8px; padding:10px; border-radius:6px; background:#070b14; border-left:4px solid var(--cyan);">' +
               '<strong style="display:block; font-size:13px; color:#fff;">' + escapeHTML(item.title) + '</strong>' +
               '<p style="margin:4px 0 0 0; font-size:11px; color:var(--muted);">' + escapeHTML(item.detail) + '</p>' +
               '</div>';
    }

    // Sidebar Toggle
    var menuBtn = $("#menuButton");
    var sidebar = $("#sidebar");
    if (menuBtn && sidebar) {
        menuBtn.addEventListener("click", function() {
            sidebar.classList.toggle("open");
        });
    }

    // URL Scanner Form
    var scanForm = $("#scanForm");
    if (scanForm) {
        scanForm.addEventListener("submit", function(e) {
            e.preventDefault();
            var url = $("#urlInput").value.trim();
            var scanBtn = $("#scanButton");
            var resultPanel = $("#resultPanel");
            setLoading(scanBtn, true);

            sendRequest("/api/scan", { url: url }).then(function(res) {
                var r = res.result;
                $("#scannedUrl").textContent = r.url;
                $("#riskScore").textContent = r.score;
                
                var badge = $("#verdictBadge");
                badge.textContent = r.verdict;
                badge.className = "verdict " + getBadgeClass(r.verdict);

                var ring = $("#scoreRing");
                if (ring) {
                    ring.style.background = "conic-gradient(" + (r.score > 50 ? '#ef4444' : '#00f2fe') + " " + r.score + "%, #1e293b " + r.score + "%)";
                }

                $("#findingsList").innerHTML = r.findings.map(findingHTML).join("");
                resultPanel.classList.remove("hidden");
                resultPanel.classList.add("show");
                resultPanel.scrollIntoView({ behavior: "smooth" });
                showToast("URL Scan Complete.");
            }).catch(function(err) {
                showToast(err.message);
            }).finally(function() {
                setLoading(scanBtn, false);
            });
        });
    }

    // Vulnerability Assessment Form
    var siteForm = $("#siteForm");
    if (siteForm) {
        siteForm.addEventListener("submit", function(e) {
            e.preventDefault();
            var url = $("#siteUrl").value.trim();
            var btn = $("#siteButton");
            var panel = $("#siteResults");
            setLoading(btn, true);

            sendRequest("/api/site-assess", { url: url }).then(function(res) {
                var r = res.result;
                $("#siteHost").textContent = r.url;
                $("#siteScore").textContent = r.score;
                $("#siteHttp").textContent = r.status_code;
                $("#siteHttps").textContent = r.https ? "Enabled" : "Not Enforced";
                $("#siteServer").textContent = r.server;

                $("#siteFindings").innerHTML = r.findings.map(findingHTML).join("");
                panel.classList.remove("hidden");
                panel.classList.add("show");
                panel.scrollIntoView({ behavior: "smooth" });
                showToast("Site Vulnerability Audit Complete.");
            }).catch(function(err) {
                showToast(err.message);
            }).finally(function() {
                setLoading(btn, false);
            });
        });
    }

    // AI Phishing & Threat Intelligence Tester
    var featureBtn = $("#featureBtn");
    if (featureBtn) {
        featureBtn.addEventListener("click", function() {
            var inputVal = $("#featureInput").value.trim();
            var resDiv = $("#featureResult");
            if (!inputVal) return showToast("Please enter a domain or text to test.");

            setLoading(featureBtn, true);
            sendRequest("/api/scan", { url: inputVal }).then(function(res) {
                var r = res.result;
                resDiv.innerHTML = '<div style="background:#070b14; padding:14px; border-radius:8px; border:1px solid var(--border); margin-top:14px;">' +
                                   '<div style="display:flex; justify-content:space-between; margin-bottom:8px;">' +
                                   '<strong>Intelligence Analysis for: ' + escapeHTML(r.url) + '</strong>' +
                                   '<span class="verdict ' + getBadgeClass(r.verdict) + '">' + r.verdict + '</span>' +
                                   '</div>' + r.findings.map(findingHTML).join("") + '</div>';
                resDiv.classList.remove("hidden");
                showToast("Intelligence feed query processed.");
            }).catch(function(err) {
                showToast(err.message);
            }).finally(function() {
                setLoading(featureBtn, false);
            });
        });
    }
});