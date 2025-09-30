document.addEventListener("DOMContentLoaded", () => {
    // Tab switching
    window.showTab = function (tab) {
        document.querySelectorAll(".form").forEach(f => f.classList.remove("active"));
        document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
        document.getElementById(tab + "Form").classList.add("active");
        document.querySelector(`.tab[onclick="showTab('${tab}')"]`).classList.add("active");
    };

    // Register Form
    const registerForm = document.getElementById("registerForm");
    registerForm.addEventListener("submit", async (e) => {
        e.preventDefault();

        const data = {
            fullName: registerForm.fullName.value,
            email: registerForm.email.value,
            phone: registerForm.phone.value,
            password: registerForm.password.value,
        };

        try {
            const res = await fetch("http://localhost:3000/api/auth/register", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(data)
            });

            const result = await res.json();
            document.getElementById("registerMsg").textContent = result.message;
            if (result.success) {
                alert("Registration successful! Please login.");
                showTab("login");
            }
        } catch (err) {
            console.error(err);
            document.getElementById("registerMsg").textContent = "Error during registration.";
        }
    });

    // Login Form
    const loginForm = document.getElementById("loginForm");
    loginForm.addEventListener("submit", async (e) => {
        e.preventDefault();

        const data = {
            email: loginForm.email.value,
            password: loginForm.password.value,
        };

        try {
            const res = await fetch("http://localhost:3000/api/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(data)
            });

            const result = await res.json();
            document.getElementById("loginMsg").textContent = result.message;

            if (result.success) {
                alert("Login successful! Welcome " + result.user.fullName);
                // Store token in localStorage for later API calls
                localStorage.setItem("token", result.token);
                // Redirect to dashboard page (create dashboard.html)
                window.location.href = "dashboard.html";
            }
        } catch (err) {
            console.error(err);
            document.getElementById("loginMsg").textContent = "Error during login.";
        }
    });
});
