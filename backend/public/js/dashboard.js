// Protect dashboard if not logged in
document.addEventListener("DOMContentLoaded", () => {
    const token = localStorage.getItem("token");
    if (!token) {
        alert("You must login first!");
        window.location.href = "index.html";
    } else {
        // show user info from localStorage if available
        const user = JSON.parse(localStorage.getItem("user") || "{}");
        if (user.fullName) {
            document.getElementById("welcomeText").textContent =
                `Welcome, ${user.fullName} 👮‍♂️`;
        }
    }
});

// Logout function
function logout() {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    window.location.href = "index.html";
}

// Load different sections
function loadSection(section) {
    const content = document.getElementById("mainContent");
    if (section === "home") {
        content.innerHTML = `
      <h2>Dashboard Home</h2>
      <p>This is your central hub for FIRs, Crime details, Arrests, Property seizures, and Final Reports.</p>
    `;
    }
}
