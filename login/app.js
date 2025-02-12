document.addEventListener("DOMContentLoaded", async function () {
    const auth0Client = await auth0.createAuth0Client({
      domain: "dev-3udbkh8oa5nlcbih.us.auth0.com",
      clientId: "UDBHQ27EBYkha6SDosKpJJqCmVuEm8Mj",
      authorizationParams: {
        redirect_uri: window.location.origin,
      },
    });
  
    if (window.location.search.includes("state=") && 
        (window.location.search.includes("code=") || 
        window.location.search.includes("error="))) {
      await auth0Client.handleRedirectCallback();
      window.history.replaceState({}, document.title, "/");
    }
  
    const isAuthenticated = await auth0Client.isAuthenticated();
    const loginButton = document.getElementById("login");
    const logoutButton = document.getElementById("logout");
    const profileElement = document.getElementById("profile");
  
    if (isAuthenticated) {
      const user = await auth0Client.getUser();
  
      profileElement.style.display = "block";
      profileElement.innerHTML = `
        <p>Welcome, ${user.name}!</p>
        <img src="${user.picture}" class="is-rounded" width="100">
      `;
  
      loginButton.classList.add("is-hidden");
      logoutButton.classList.remove("is-hidden");
    } else {
      profileElement.style.display = "none";
      loginButton.classList.remove("is-hidden");
      logoutButton.classList.add("is-hidden");
    }
  
    loginButton.addEventListener("click", () => {
      auth0Client.loginWithRedirect();
    });
  
    logoutButton.addEventListener("click", () => {
      auth0Client.logout({
        logoutParams: { returnTo: window.location.origin },
      });
    });
  });
  