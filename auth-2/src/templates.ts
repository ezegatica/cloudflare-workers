import { AppListItem } from "./interfaces";

export function loginPage(app: AppListItem): string {
  return `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Login to ${app.displayName}</title></head>
<body>
  <h1>Login to ${app.displayName}</h1>
  <form id="login-form">
    <input type="hidden" name="app" id="app" value="${app.id}">
    <label>Email: <input type="email" name="email" required></label><br>
    <label>Password: <input type="password" name="password" required></label><br>
    <button type="submit">Login</button>
  </form>
  <button id="google-login">Login with Google</button>
  <div id="error" style="color:red;"></div>
  <script>
    (function() {
      const form = document.getElementById('login-form');
      const errorDiv = document.getElementById('error');
      form.addEventListener('submit', async e => {
        e.preventDefault();
        errorDiv.textContent = '';
        const data = new URLSearchParams(new FormData(form));
        const res = await fetch('/login', { method: 'POST', body: data });
        const text = await res.text();
        if (!res.ok) {
          try { errorDiv.textContent = JSON.parse(text).error; } catch { errorDiv.textContent = text; }
          return;
        }
        const json = JSON.parse(text);
        window.location.href = json.redirect;
      });
      const googleBtn = document.getElementById('google-login');
      googleBtn.addEventListener('click', () => {
        const app = (document.getElementById('app')).value;
        window.location.href = \`/auth/google?app=\${app}\`;
      });
    })();
</script>
</body>
</html>`;
}

export function registerPage(app: AppListItem): string {
  return `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Register for ${app.displayName}</title></head>
<body>
  <h1>Register for ${app.displayName}</h1>
  <form id="register-form">
    <input type="hidden" name="app" id="app" value="${app.id}">
    <label>Email: <input type="email" name="email" required></label><br>
    <label>Password: <input type="password" name="password" required></label><br>
    <button type="submit">Register</button>
  </form>
  <div id="error" style="color:red;"></div>
  <script>
    (function() {
      const form = document.getElementById('register-form');
      const errorDiv = document.getElementById('error');
      form.addEventListener('submit', async e => {
        e.preventDefault();
        errorDiv.textContent = '';
        const data = new URLSearchParams(new FormData(form));
        const res = await fetch('/register', { method: 'POST', body: data });
        const text = await res.text();
        if (!res.ok) {
          try { errorDiv.textContent = JSON.parse(text).error; } catch { errorDiv.textContent = text; }
          return;
        }
        const json = JSON.parse(text);
        window.location.href = json.redirect;
      });
    })();
</script>
</body>
</html>`;
}