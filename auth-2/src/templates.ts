import { AppListItem } from "./interfaces";

export function loginPage(app: AppListItem, publicKey: string): string {
  return `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Login to ${app.displayName}</title></head>
<body>
  <h1>Login to ${app.displayName}</h1>
  <form id="login-form">
    <input type="hidden" name="app" id="app" value="${app.id}">
    <input type="hidden" name="timestamp" id="timestamp" value="">
    <label>Email: <input type="email" name="email" required></label><br>
    <label>Password: <input type="password" id="password-input" required></label><br>
    <input type="hidden" name="encryptedPassword" id="encrypted-password" value="">
    <button type="submit">Login</button>
  </form>
  <button id="google-login">Login with Google</button>
  <div id="error" style="color:red;"></div>
  <script src="https://cdn.jsdelivr.net/npm/jsencrypt@3.3.2/bin/jsencrypt.min.js"></script>
  <script>
    (function() {
      const form = document.getElementById('login-form');
      const errorDiv = document.getElementById('error');
      form.addEventListener('submit', async e => {
        e.preventDefault();
        errorDiv.textContent = '';
        
        // Get the timestamp
        const timestamp = Math.floor(Date.now() / 1000).toString();
        document.getElementById('timestamp').value = timestamp;
        
        // Encrypt timestamp with password - timestamp first so we can safely split later
        const passwordInput = document.getElementById('password-input').value;
        const dataToEncrypt = timestamp + '|' + passwordInput; // Timestamp first, then password
        
        try {
          // Encrypt using public key
          const encrypt = new JSEncrypt();
          encrypt.setPublicKey(\`${publicKey}\`);
          
          // JSEncrypt uses PKCS#1 v1.5 padding by default
          const encrypted = encrypt.encrypt(dataToEncrypt);
          
          if (!encrypted) {
            errorDiv.textContent = 'Encryption failed';
            return;
          }
          
          document.getElementById('encrypted-password').value = encrypted;
          
          // Prepare form data without the plain password
          const formData = new FormData(form);
          const data = new URLSearchParams(formData);
          
          const res = await fetch('/login', { method: 'POST', body: data });
          const text = await res.text();
          if (!res.ok) {
            try { 
              const jsonError = JSON.parse(text);
              errorDiv.textContent = jsonError.error || 'Login failed'; 
            } catch { 
              errorDiv.textContent = text || 'Login failed'; 
            }
            return;
          }
          const json = JSON.parse(text);
          window.location.href = json.redirect;
        } catch (err) {
          errorDiv.textContent = 'Encryption error: ' + err.message;
        }
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

export function registerPage(app: AppListItem, publicKey: string): string {
  return `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Register for ${app.displayName}</title></head>
<body>
  <h1>Register for ${app.displayName}</h1>
  <form id="register-form">
    <input type="hidden" name="app" id="app" value="${app.id}">
    <input type="hidden" name="timestamp" id="timestamp" value="">
    <label>Email: <input type="email" name="email" required></label><br>
    <label>Password: <input type="password" id="password-input" required></label><br>
    <input type="hidden" name="encryptedPassword" id="encrypted-password" value="">
    <button type="submit">Register</button>
  </form>
  <div id="error" style="color:red;"></div>
  <script src="https://cdn.jsdelivr.net/npm/jsencrypt@3.3.2/bin/jsencrypt.min.js"></script>
  <script>
    (function() {
      const form = document.getElementById('register-form');
      const errorDiv = document.getElementById('error');
      form.addEventListener('submit', async e => {
        e.preventDefault();
        errorDiv.textContent = '';
        
        // Get the timestamp
        const timestamp = Math.floor(Date.now() / 1000).toString();
        document.getElementById('timestamp').value = timestamp;
        
        // Encrypt timestamp with password - timestamp first so we can safely split later
        const passwordInput = document.getElementById('password-input').value;
        const dataToEncrypt = timestamp + '|' + passwordInput; // Timestamp first, then password
        
        try {
          // Encrypt using public key
          const encrypt = new JSEncrypt();
          encrypt.setPublicKey(\`${publicKey}\`);
          
          // JSEncrypt uses PKCS#1 v1.5 padding by default
          const encrypted = encrypt.encrypt(dataToEncrypt);
          
          if (!encrypted) {
            errorDiv.textContent = 'Encryption failed';
            return;
          }
          
          document.getElementById('encrypted-password').value = encrypted;
          
          // Prepare form data without the plain password
          const formData = new FormData(form);
          const data = new URLSearchParams(formData);
          
          const res = await fetch('/register', { method: 'POST', body: data });
          const text = await res.text();
          if (!res.ok) {
            try { 
              const jsonError = JSON.parse(text);
              errorDiv.textContent = jsonError.error || 'Registration failed'; 
            } catch { 
              errorDiv.textContent = text || 'Registration failed'; 
            }
            return;
          }
          const json = JSON.parse(text);
          window.location.href = json.redirect;
        } catch (err) {
          errorDiv.textContent = 'Encryption error: ' + err.message;
        }
      });
    })();
</script>
</body>
</html>`;
}