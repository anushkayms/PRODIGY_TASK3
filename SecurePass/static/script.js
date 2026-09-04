(() => {
  const passwordInput = document.getElementById("password-input");
  const toggleBtn = document.getElementById("toggle-visibility");
  const eyeOpen = document.getElementById("eye-open");
  const eyeClosed = document.getElementById("eye-closed");
  const analyzeBtn = document.getElementById("analyze-btn");
  const formMessage = document.getElementById("form-message");
  const scanSequence = document.getElementById("scan-sequence");
  const scanLine = document.getElementById("scan-line");
  const results = document.getElementById("results");

  const scoreValue = document.getElementById("score-value");
  const strengthValue = document.getElementById("strength-value");
  const riskValue = document.getElementById("risk-value");
  const meterFill = document.getElementById("meter-fill");
  const meterTrack = document.getElementById("meter-track");
  const meterStrengthLabel = document.getElementById("meter-strength-label");
  const signalsList = document.getElementById("signals-list");
  const recommendationsList = document.getElementById("recommendations-list");

  const SCAN_STEPS = [
    "Initializing security analysis...",
    "Analyzing password complexity...",
    "Detecting predictable patterns...",
    "Evaluating security risks...",
    "Generating recommendations...",
  ];

  let currentAnimationToken = 0;

  // --- Show / hide password ---
  toggleBtn.addEventListener("click", () => {
    const isPassword = passwordInput.type === "password";
    passwordInput.type = isPassword ? "text" : "password";
    eyeOpen.style.display = isPassword ? "none" : "block";
    eyeClosed.style.display = isPassword ? "block" : "none";
    toggleBtn.setAttribute("aria-label", isPassword ? "Hide password" : "Show password");
  });

  // --- Fetch analysis from backend ---
  async function fetchAnalysis(password) {
    const response = await fetch("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password }),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Analysis failed.");
    }
    return data;
  }

  function strengthToneClass(strength) {
    switch (strength) {
      case "WEAK": return "tone-weak";
      case "MODERATE": return "tone-moderate";
      case "STRONG": return "tone-strong";
      case "VERY STRONG": return "tone-very-strong";
      default: return "";
    }
  }

  function animateScoreCounter(target) {
    const duration = 500;
    const start = performance.now();
    const from = parseInt(scoreValue.textContent, 10) || 0;

    function step(now) {
      const progress = Math.min((now - start) / duration, 1);
      const value = Math.round(from + (target - from) * progress);
      scoreValue.textContent = value;
      if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  function renderResults(data) {
    animateScoreCounter(data.score);

    strengthValue.textContent = data.strength;
    strengthValue.className = "stat-value " + strengthToneClass(data.strength);

    riskValue.textContent = data.risk_level;
    riskValue.className = "stat-value " + strengthToneClass(data.strength);

    meterStrengthLabel.textContent = data.strength;
    meterTrack.setAttribute("aria-valuenow", data.score);
    meterFill.style.width = data.score + "%";
    meterFill.className = "meter-fill-bar " + strengthToneClass(data.strength);

    signalsList.innerHTML = "";
    data.signals.forEach((signal) => {
      const li = document.createElement("li");
      li.className = signal.type;
      const icon = document.createElement("span");
      icon.className = "signal-icon";
      icon.textContent = signal.type === "positive" ? "✓" : "⚠";
      const text = document.createElement("span");
      text.textContent = signal.text;
      li.appendChild(icon);
      li.appendChild(text);
      signalsList.appendChild(li);
    });

    recommendationsList.innerHTML = "";
    data.recommendations.forEach((rec) => {
      const li = document.createElement("li");
      li.textContent = rec;
      recommendationsList.appendChild(li);
    });

    results.hidden = false;
    document.body.classList.add("results-shown");
  }

  // --- Full analysis with the animated scan sequence (button click) ---
  async function runFullAnalysis() {
    const password = passwordInput.value;
    formMessage.textContent = "";

    if (!password) {
      formMessage.textContent = "Please enter a password to begin the security analysis.";
      results.hidden = true;
      document.body.classList.remove("results-shown");
      return;
    }

    const myToken = ++currentAnimationToken;
    analyzeBtn.disabled = true;
    scanSequence.hidden = false;

    for (const line of SCAN_STEPS) {
      if (myToken !== currentAnimationToken) return; // superseded by a newer click
      scanLine.textContent = line;
      await new Promise((r) => setTimeout(r, 260));
    }

    try {
      const data = await fetchAnalysis(password);
      if (myToken !== currentAnimationToken) return;
      scanLine.textContent = "ANALYSIS COMPLETE";
      await new Promise((r) => setTimeout(r, 200));
      renderResults(data);
    } catch (err) {
      formMessage.textContent = err.message;
    } finally {
      if (myToken === currentAnimationToken) {
        analyzeBtn.disabled = false;
        scanSequence.hidden = true;
      }
    }
  }

  analyzeBtn.addEventListener("click", runFullAnalysis);

  passwordInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") runFullAnalysis();
  });

  // --- Clear results if the user empties the field, but don't auto-analyze ---
  passwordInput.addEventListener("input", () => {
    if (!passwordInput.value) {
      results.hidden = true;
      document.body.classList.remove("results-shown");
      formMessage.textContent = "";
    }
  });
})();
