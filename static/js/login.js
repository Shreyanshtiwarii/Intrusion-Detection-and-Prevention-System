document.getElementById("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;
  const errorBox = document.getElementById("loginError");
  const btn = document.getElementById("loginBtn");

  errorBox.classList.remove("show");
  btn.disabled = true;
  btn.innerHTML = '<span class="loader"></span> Signing In...';

  try {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();

    if (data.success) {
      window.location.href = "/dashboard";
    } else {
      errorBox.textContent = data.error || "Login failed";
      errorBox.classList.add("show");
      btn.disabled = false;
      btn.innerHTML = '<i class="fa-solid fa-lock"></i> Sign In';
    }
  } catch (err) {
    errorBox.textContent = "Unable to reach server. Please try again.";
    errorBox.classList.add("show");
    btn.disabled = false;
    btn.innerHTML = '<i class="fa-solid fa-lock"></i> Sign In';
  }
});
