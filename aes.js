/* === CONFIGURACIÓN DE PARÁMETROS === */
const SALT_LEN = 16;      // bytes
const IV_LEN = 12;        // AES-GCM recomendación 12 bytes
const PBKDF2_ITERS = 200000; // Aumentado para más seguridad
const KEY_LEN = 256;      // bits

/* === ELEMENTOS DOM === */
const logContainer = document.getElementById('log');
const loadingOverlay = document.getElementById('loadingOverlay');

/* === SISTEMA DE LOGGING MEJORADO === */
function log(message, type = 'info') {
  console.log(message);
  
  const logEntry = document.createElement('div');
  logEntry.className = `log-entry ${type}`;
  
  const icon = document.createElement('i');
  switch(type) {
    case 'success':
      icon.className = 'fas fa-check-circle';
      break;
    case 'error':
      icon.className = 'fas fa-exclamation-circle';
      break;
    case 'warning':
      icon.className = 'fas fa-exclamation-triangle';
      break;
    default:
      icon.className = 'fas fa-info-circle';
  }
  
  const span = document.createElement('span');
  span.textContent = message;
  
  logEntry.appendChild(icon);
  logEntry.appendChild(span);
  
  // Limpiar logs antiguos si hay muchos
  if (logContainer.children.length > 10) {
    logContainer.removeChild(logContainer.firstChild);
  }
  
  logContainer.appendChild(logEntry);
  logContainer.scrollTop = logContainer.scrollHeight;
}

/* === SISTEMA DE LOADING === */
function showLoading(message = 'Procesando...') {
  const spinner = loadingOverlay.querySelector('.loading-spinner p');
  spinner.textContent = message;
  loadingOverlay.classList.add('show');
}

function hideLoading() {
  loadingOverlay.classList.remove('show');
}

/* === UTILITIES (Mejoradas) === */
function bufToBase64(buf){
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function base64ToBuf(b64){
  const s = atob(b64);
  const arr = new Uint8Array(s.length);
  for(let i=0;i<s.length;i++) arr[i]=s.charCodeAt(i);
  return arr.buffer;
}

function concatUint8Arrays(...arrays){
  const total = arrays.reduce((s,a)=>s+a.byteLength,0);
  const out = new Uint8Array(total);
  let offset=0;
  for(const a of arrays){ out.set(new Uint8Array(a), offset); offset += a.byteLength; }
  return out.buffer;
}

function downloadBlob(blob, filename){
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(()=>URL.revokeObjectURL(url), 10000);
}

function formatFileSize(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function getMimeTypeFromExtension(filename) {
  console.log(`Detectando MIME type para: "${filename}"`);
  
  // Verificar que el filename no esté vacío y tenga al menos un punto
  if (!filename || typeof filename !== 'string') {
    console.log('Filename inválido:', filename);
    return 'application/octet-stream';
  }
  
  // Extraer extensión de manera más robusta
  const parts = filename.toLowerCase().split('.');
  if (parts.length < 2) {
    console.log('No se encontró extensión en:', filename);
    return 'application/octet-stream';
  }
  
  const ext = parts[parts.length - 1]; // Obtener la última parte después del último punto
  console.log(`Extensión detectada: "${ext}"`);
  
  const mimeTypes = {
    // Imágenes
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'png': 'image/png',
    'gif': 'image/gif',
    'webp': 'image/webp',
    'bmp': 'image/bmp',
    'svg': 'image/svg+xml',
    'ico': 'image/x-icon',
    'tiff': 'image/tiff',
    'tif': 'image/tiff',
    
    // Documentos
    'pdf': 'application/pdf',
    'doc': 'application/msword',
    'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'xls': 'application/vnd.ms-excel',
    'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'ppt': 'application/vnd.ms-powerpoint',
    'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    
    // Texto
    'txt': 'text/plain',
    'html': 'text/html',
    'css': 'text/css',
    'js': 'text/javascript',
    'json': 'application/json',
    'xml': 'text/xml',
    
    // Audio
    'mp3': 'audio/mpeg',
    'wav': 'audio/wav',
    'ogg': 'audio/ogg',
    'aac': 'audio/aac',
    
    // Video
    'mp4': 'video/mp4',
    'avi': 'video/x-msvideo',
    'mov': 'video/quicktime',
    'webm': 'video/webm',
    
    // Archivos comprimidos
    'zip': 'application/zip',
    'rar': 'application/x-rar-compressed',
    '7z': 'application/x-7z-compressed',
    'tar': 'application/x-tar',
    'gz': 'application/gzip'
  };
  
  const mimeType = mimeTypes[ext] || 'application/octet-stream';
  console.log(`MIME type final: "${mimeType}" para extensión: "${ext}"`);
  
  return mimeType;
}

function detectImageTypeFromBytes(arrayBuffer) {
  const bytes = new Uint8Array(arrayBuffer.slice(0, 12)); // Leer los primeros 12 bytes
  
  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (bytes.length >= 8 && 
      bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47 &&
      bytes[4] === 0x0D && bytes[5] === 0x0A && bytes[6] === 0x1A && bytes[7] === 0x0A) {
    return 'image/png';
  }
  
  // JPEG: FF D8 FF
  if (bytes.length >= 3 && bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) {
    return 'image/jpeg';
  }
  
  // GIF: GIF87a o GIF89a
  if (bytes.length >= 6 && 
      bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46 &&
      bytes[3] === 0x38 && (bytes[4] === 0x37 || bytes[4] === 0x39) && bytes[5] === 0x61) {
    return 'image/gif';
  }
  
  // WebP: RIFF....WEBP
  if (bytes.length >= 12 &&
      bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 &&
      bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50) {
    return 'image/webp';
  }
  
  // BMP: BM
  if (bytes.length >= 2 && bytes[0] === 0x42 && bytes[1] === 0x4D) {
    return 'image/bmp';
  }
  
  return null; // No es una imagen reconocida
}

/* === SISTEMA DE PESTAÑAS === */
function initTabs() {
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');
  
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.dataset.tab;
      
      // Remover clases activas
      tabBtns.forEach(b => b.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));
      
      // Activar pestaña seleccionada
      btn.classList.add('active');
      document.getElementById(`${targetTab}-tab`).classList.add('active');
    });
  });
}

/* === SISTEMA DE CONTRASEÑAS === */
function initPasswordToggles() {
  const toggles = document.querySelectorAll('.toggle-password');
  
  toggles.forEach(toggle => {
    toggle.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      
      const targetId = toggle.dataset.target;
      const input = document.getElementById(targetId);
      const icon = toggle.querySelector('i');
      
      if (!input) return;
      
      // Guardar el valor y posición del cursor
      const currentValue = input.value;
      const cursorPosition = input.selectionStart;
      
      if (input.type === 'password') {
        input.type = 'text';
        icon.className = 'fas fa-eye-slash';
        toggle.setAttribute('title', 'Ocultar contraseña');
      } else {
        input.type = 'password';
        icon.className = 'fas fa-eye';
        toggle.setAttribute('title', 'Mostrar contraseña');
      }
      
      // Restaurar el valor y posición del cursor
      input.value = currentValue;
      input.setSelectionRange(cursorPosition, cursorPosition);
      
      // Forzar que mantenga el foco si lo tenía
      if (document.activeElement === input) {
        input.focus();
      }
    });
  });
}

function calculatePasswordStrength(password) {
  let score = 0;
  let feedback = 'Muy débil';
  let color = '#dc2626';
  
  if (password.length >= 8) score += 1;
  if (password.length >= 12) score += 1;
  if (/[a-z]/.test(password)) score += 1;
  if (/[A-Z]/.test(password)) score += 1;
  if (/[0-9]/.test(password)) score += 1;
  if (/[^A-Za-z0-9]/.test(password)) score += 1;
  
  switch(score) {
    case 0:
    case 1:
      feedback = 'Muy débil';
      color = '#dc2626';
      break;
    case 2:
    case 3:
      feedback = 'Débil';
      color = '#d97706';
      break;
    case 4:
      feedback = 'Moderada';
      color = '#059669';
      break;
    case 5:
    case 6:
      feedback = 'Fuerte';
      color = '#047857';
      break;
  }
  
  return { score: (score / 6) * 100, feedback, color };
}

function initPasswordStrength() {
  const passwordInputs = document.querySelectorAll('input[type="password"]');
  
  passwordInputs.forEach(input => {
    const container = input.closest('.input-group');
    const strengthBar = container?.querySelector('.strength-fill');
    const strengthText = container?.querySelector('.strength-text');
    
    if (strengthBar && strengthText) {
      input.addEventListener('input', () => {
        const strength = calculatePasswordStrength(input.value);
        strengthBar.style.width = `${strength.score}%`;
        strengthBar.style.backgroundColor = strength.color;
        strengthText.textContent = strength.feedback;
        strengthText.style.color = strength.color;
      });
    }
  });
}

/* === DRAG & DROP === */
function initDragAndDrop() {
  const dropZones = document.querySelectorAll('.file-drop-zone');
  
  dropZones.forEach(zone => {
    const input = zone.querySelector('input[type="file"]');
    
    zone.addEventListener('click', () => input.click());
    
    zone.addEventListener('dragover', (e) => {
      e.preventDefault();
      zone.classList.add('dragover');
    });
    
    zone.addEventListener('dragleave', () => {
      zone.classList.remove('dragover');
    });
    
    zone.addEventListener('drop', (e) => {
      e.preventDefault();
      zone.classList.remove('dragover');
      
      const files = e.dataTransfer.files;
      if (files.length > 0) {
        input.files = files;
        input.dispatchEvent(new Event('change'));
      }
    });
  });
}

function showFileInfo(file, containerId) {
  const container = document.getElementById(containerId);
  container.style.display = 'block';
  
  const icon = file.type.startsWith('image/') ? 'fas fa-image' : 'fas fa-file';
  
  container.innerHTML = `
    <i class="${icon}"></i>
    <div class="file-details">
      <h4>${file.name}</h4>
      <p>Tamaño: ${formatFileSize(file.size)} | Tipo: ${file.type || 'Desconocido'}</p>
    </div>
  `;
}

/* === VISTA PREVIA DE IMÁGENES === */
function showImagePreview(file, elementId) {
  const area = document.getElementById(elementId);
  
  if (!area) {
    console.error(`Elemento con ID '${elementId}' no encontrado`);
    log(`Error: Elemento ${elementId} no encontrado`, 'error');
    return;
  }
  
  area.innerHTML = '';
  console.log(`Mostrando vista previa para: ${file.name}, tipo: ${file.type}, en elemento: ${elementId}`);
  console.log(`¿Es imagen? ${file.type.startsWith('image/')}`);
  
  if (!file || !file.type.startsWith('image/')) {
    const message = file ? 
      `Archivo: ${file.name} (Tipo: ${file.type || 'desconocido'}) - No es una imagen` :
      'Sin vista previa disponible';
    area.innerHTML = `<p style="color: var(--text-secondary); font-style: italic;">${message}</p>`;
    console.log(`No es imagen o archivo nulo. Razón: ${!file ? 'archivo nulo' : 'tipo no es imagen (' + file.type + ')'}`);
    return;
  }
  
  const url = URL.createObjectURL(file);
  const img = document.createElement('img');
  
  img.onload = () => {
    URL.revokeObjectURL(url);
    log(`Vista previa cargada: ${file.name}`, 'success');
    console.log(`Imagen cargada exitosamente: ${file.name}`);
  };
  
  img.onerror = () => {
    URL.revokeObjectURL(url);
    area.innerHTML = '<p style="color: var(--danger-color); font-style: italic;">Error al cargar la imagen</p>';
    log(`Error al cargar vista previa de: ${file.name}`, 'error');
    console.error(`Error al cargar imagen: ${file.name}`);
  };
  
  img.src = url;
  area.appendChild(img);
  console.log(`Imagen agregada al DOM, src: ${url}`);
}

/* === CRYPTO HELPERS === */
async function deriveKeyFromPassword(password, salt, mode = 'GCM'){
  const enc = new TextEncoder();
  const passKey = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  
  // Para ECB simulamos usando CBC (Web Crypto API no soporta ECB directamente)
  const algorithmName = mode === 'ECB' ? 'AES-CBC' : mode === 'CBC' ? 'AES-CBC' : 'AES-GCM';
  
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', salt: salt, iterations: PBKDF2_ITERS, hash:'SHA-256'},
    passKey,
    {name: algorithmName, length: KEY_LEN},
    false,
    ['encrypt','decrypt']
  );
}

// Función para agregar padding PKCS#7 (necesario para ECB y CBC)
function addPKCS7Padding(data, blockSize = 16) {
  const paddingLength = blockSize - (data.byteLength % blockSize);
  const paddedData = new Uint8Array(data.byteLength + paddingLength);
  paddedData.set(new Uint8Array(data));
  
  // Llenar el padding con el valor del tamaño del padding
  for (let i = data.byteLength; i < paddedData.length; i++) {
    paddedData[i] = paddingLength;
  }
  
  return paddedData.buffer;
}

// Función para quitar padding PKCS#7
function removePKCS7Padding(data) {
  const bytes = new Uint8Array(data);
  const paddingLength = bytes[bytes.length - 1];
  
  // Verificar que el padding sea válido
  if (paddingLength > 16 || paddingLength === 0) {
    throw new Error('Padding inválido');
  }
  
  for (let i = bytes.length - paddingLength; i < bytes.length; i++) {
    if (bytes[i] !== paddingLength) {
      throw new Error('Padding inválido');
    }
  }
  
  return data.slice(0, data.byteLength - paddingLength);
}

// Función para ECB real usando CryptoJS
async function encryptECB(data, password, salt) {
  try {
    // Derivar clave usando PBKDF2 similar a Web Crypto API
    const saltWA = CryptoJS.lib.WordArray.create(salt);
    const key = CryptoJS.PBKDF2(password, saltWA, {
      keySize: 256/32,
      iterations: 200000,
      hasher: CryptoJS.algo.SHA256
    });
    
    // Convertir datos a WordArray de CryptoJS
    const dataWA = CryptoJS.lib.WordArray.create(data);
    
    // Cifrar usando ECB
    const encryptedWA = CryptoJS.AES.encrypt(dataWA, key, { 
      mode: CryptoJS.mode.ECB, 
      padding: CryptoJS.pad.Pkcs7 
    });
    
    // Convertir resultado a ArrayBuffer
    const encryptedBytes = cryptoJSToUint8Array(encryptedWA.ciphertext);
    return encryptedBytes.buffer;
    
  } catch (error) {
    throw new Error('Error en cifrado ECB: ' + error.message);
  }
}

// Función para descifrado ECB real usando CryptoJS
async function decryptECB(data, password, salt) {
  try {
    // Derivar clave usando PBKDF2 similar a Web Crypto API
    const saltWA = CryptoJS.lib.WordArray.create(salt);
    const key = CryptoJS.PBKDF2(password, saltWA, {
      keySize: 256/32,
      iterations: 200000,
      hasher: CryptoJS.algo.SHA256
    });
    
    // Convertir datos cifrados a WordArray de CryptoJS
    const cipherWA = CryptoJS.lib.WordArray.create(data);
    
    // Crear objeto CipherParams
    const cipherParams = CryptoJS.lib.CipherParams.create({
      ciphertext: cipherWA
    });
    
    // Descifrar usando ECB
    const decryptedWA = CryptoJS.AES.decrypt(cipherParams, key, { 
      mode: CryptoJS.mode.ECB, 
      padding: CryptoJS.pad.Pkcs7 
    });
    
    // Convertir resultado a ArrayBuffer
    const decryptedBytes = cryptoJSToUint8Array(decryptedWA);
    return decryptedBytes.buffer;
    
  } catch (error) {
    throw new Error('Error en descifrado ECB: ' + error.message);
  }
}

async function encryptArrayBuffer(arrayBuffer, password, mode = 'GCM'){
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  let iv, key, cipher;
  
  console.log(`Cifrando con modo: ${mode}`);
  
  switch(mode) {
    case 'ECB':
      // ECB real usando CryptoJS
      const paddedData = addPKCS7Padding(arrayBuffer);
      cipher = await encryptECB(paddedData, password, salt.buffer);
      // Formato: [salt(16)] [ciphertext...]
      return concatUint8Arrays(salt.buffer, cipher);
      
    case 'CBC':
      // CBC usa IV de 16 bytes
      iv = crypto.getRandomValues(new Uint8Array(16));
      key = await deriveKeyFromPassword(password, salt.buffer, 'CBC');
      const paddedDataCBC = addPKCS7Padding(arrayBuffer);
      cipher = await crypto.subtle.encrypt({name:'AES-CBC', iv: iv}, key, paddedDataCBC);
      // Formato: [salt(16)] [iv(16)] [ciphertext...]
      return concatUint8Arrays(salt.buffer, iv.buffer, cipher);
      
    case 'GCM':
    default:
      // GCM usa IV de 12 bytes (modo original)
      iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
      key = await deriveKeyFromPassword(password, salt.buffer, 'GCM');
      cipher = await crypto.subtle.encrypt({name:'AES-GCM', iv: iv}, key, arrayBuffer);
      // Formato: [salt(16)] [iv(12)] [ciphertext...]
      return concatUint8Arrays(salt.buffer, iv.buffer, cipher);
  }
}

async function decryptArrayBuffer(encryptedBuffer, password, mode = 'GCM'){
  const view = new Uint8Array(encryptedBuffer);
  const salt = view.slice(0, SALT_LEN).buffer;
  let iv, ciphertext, key;
  
  console.log(`Descifrando con modo: ${mode}`);
  
  switch(mode) {
    case 'ECB':
      // ECB no tiene IV
      ciphertext = view.slice(SALT_LEN).buffer;
      const decryptedECB = await decryptECB(ciphertext, password, salt);
      return removePKCS7Padding(decryptedECB);
      
    case 'CBC':
      // CBC usa IV de 16 bytes
      iv = view.slice(SALT_LEN, SALT_LEN + 16).buffer;
      ciphertext = view.slice(SALT_LEN + 16).buffer;
      key = await deriveKeyFromPassword(password, salt, 'CBC');
      const decryptedCBC = await crypto.subtle.decrypt({name:'AES-CBC', iv: iv}, key, ciphertext);
      return removePKCS7Padding(decryptedCBC);
      
    case 'GCM':
    default:
      // GCM usa IV de 12 bytes (modo original)
      iv = view.slice(SALT_LEN, SALT_LEN + IV_LEN).buffer;
      ciphertext = view.slice(SALT_LEN + IV_LEN).buffer;
      key = await deriveKeyFromPassword(password, salt, 'GCM');
      return crypto.subtle.decrypt({name:'AES-GCM', iv: iv}, key, ciphertext);
  }
}

/* === HANDLERS DE TEXTO === */
async function handleEncryptText() {
  const plainText = document.getElementById('textPlain').value;
  const pwd = document.getElementById('pwdText').value;
  const mode = document.getElementById('textMode') ? document.getElementById('textMode').value : 'GCM';
  
  if (!plainText || !pwd) {
    log('Por favor, escribe el texto y la contraseña', 'warning');
    return;
  }
  
  try {
    showLoading(`Cifrando texto con AES-${mode}...`);
    log(`Iniciando cifrado de texto con modo ${mode}...`);
    
    // Mostrar la sección de proceso detallado
    showEncryptionProcess();
    
    // Paso 1: Generar salt
    animateStep(1);
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
    updateStep1(salt);
    await new Promise(resolve => setTimeout(resolve, 800));
    
    // Paso 2: Derivar clave
    animateStep(2);
    const enc = new TextEncoder();
    const passKey = await crypto.subtle.importKey('raw', enc.encode(pwd), 'PBKDF2', false, ['deriveKey']);
    
    let derivedKey;
    if (mode === 'ECB') {
      // Para ECB, no usamos Web Crypto API sino CryptoJS
      updateStep2(pwd, salt, null);
    } else {
      const algorithm = mode === 'CBC' ? 'AES-CBC' : 'AES-GCM';
      derivedKey = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: salt, iterations: 200000, hash: 'SHA-256' },
        passKey,
        { name: algorithm, length: 256 },
        true, // Permitir exportación para mostrar
        ['encrypt']
      );
      updateStep2(pwd, salt, derivedKey);
    }
    await new Promise(resolve => setTimeout(resolve, 800));
    
    // Paso 3: Generar IV (si aplica)
    animateStep(3);
    let iv;
    if (mode === 'GCM') {
      iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
      updateStep3(iv, mode);
    } else if (mode === 'CBC') {
      iv = crypto.getRandomValues(new Uint8Array(16));
      updateStep3(iv, mode);
    } else {
      // ECB no usa IV
      updateStep3(new Uint8Array(), mode);
    }
    await new Promise(resolve => setTimeout(resolve, 800));
    
    // Paso 4: Cifrar
    animateStep(4);
    const dataBuf = enc.encode(plainText);
    let cipher;
    
    if (mode === 'ECB') {
      const paddedData = addPKCS7Padding(dataBuf);
      cipher = await encryptECB(paddedData, pwd, salt.buffer);
    } else if (mode === 'CBC') {
      const paddedData = addPKCS7Padding(dataBuf);
      cipher = await crypto.subtle.encrypt({name:'AES-CBC', iv: iv}, derivedKey, paddedData);
    } else {
      cipher = await crypto.subtle.encrypt({name:'AES-GCM', iv: iv}, derivedKey, dataBuf);
    }
    
    const cipherBytes = new Uint8Array(cipher);
    updateStep4(plainText, mode, cipherBytes);
    await new Promise(resolve => setTimeout(resolve, 800));
    
    // Paso 5: Formato final
    animateStep(5);
    let encBuf;
    if (mode === 'ECB') {
      encBuf = concatUint8Arrays(salt.buffer, cipher);
    } else if (mode === 'CBC') {
      encBuf = concatUint8Arrays(salt.buffer, iv.buffer, cipher);
    } else {
      encBuf = concatUint8Arrays(salt.buffer, iv.buffer, cipher);
    }
    
    const base64Result = bufToBase64(encBuf);
    updateStep5(base64Result, mode, encBuf.byteLength);
    
    // Mostrar resultado final
    document.getElementById('textCipher').value = base64Result;
    document.getElementById('btnCopyResult').style.display = 'inline-flex';
    
    log(`¡Texto cifrado exitosamente con AES-${mode}! Revisa el proceso detallado arriba.`, 'success');
    hideLoading();
  } catch(e) {
    console.error(e);
    log('Error al cifrar texto: ' + e.message, 'error');
    hideLoading();
  }
}

async function handleDecryptText() {
  const cipherBase64 = document.getElementById('textCipher').value;
  const pwd = document.getElementById('pwdText').value;
  const mode = document.getElementById('textMode') ? document.getElementById('textMode').value : 'GCM';
  
  if (!cipherBase64 || !pwd) {
    log('Por favor, pega el texto cifrado y la contraseña', 'warning');
    return;
  }
  
  try {
    showLoading(`Descifrando texto con AES-${mode}...`);
    log(`Iniciando descifrado de texto con modo ${mode}...`);
    
    const encBuf = base64ToBuf(cipherBase64);
    const decBuf = await decryptArrayBuffer(encBuf, pwd, mode);
    const dec = new TextDecoder();
    const decryptedText = dec.decode(decBuf);
    
    document.getElementById('textPlain').value = decryptedText;
    log(`¡Texto descifrado exitosamente con AES-${mode}!`, 'success');
    hideLoading();
  } catch(e) {
    console.error(e);
    log('Error al descifrar. Verifique la contraseña y el modo: ' + e.message, 'error');
    hideLoading();
  }
}

function handleCopyResult() {
  const textToCopy = document.getElementById('textCipher').value;
  navigator.clipboard.writeText(textToCopy).then(() => {
    log('Texto copiado al portapapeles', 'success');
    
    const btn = document.getElementById('btnCopyResult');
    const originalText = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-check"></i> ¡Copiado!';
    setTimeout(() => {
      btn.innerHTML = originalText;
    }, 2000);
  }).catch(() => {
    log('Error al copiar al portapapeles', 'error');
  });
}

/* === HANDLERS DE ARCHIVOS === */
async function handleEncryptFile() {
  const file = document.getElementById('fileEncrypt').files[0];
  const pwd = document.getElementById('pwdEncrypt').value;
  const mode = document.getElementById('fileMode') ? document.getElementById('fileMode').value : 'GCM';
  
  if (!file || !pwd) {
    log('Por favor, selecciona un archivo y una contraseña', 'warning');
    return;
  }
  
  try {
    showLoading(`Cifrando ${file.name} con AES-${mode}...`);
    log(`Iniciando cifrado de ${file.name} (${formatFileSize(file.size)}) con modo ${mode}`);
    
    const ab = await file.arrayBuffer();
    const encBuf = await encryptArrayBuffer(ab, pwd, mode);
    const blob = new Blob([encBuf], {type:'application/octet-stream'});
    const outName = file.name + `.${mode.toLowerCase()}.aes`;
    
    downloadBlob(blob, outName);
    log(`¡Archivo cifrado y descargado: ${outName}!`, 'success');
    hideLoading();
  } catch(e) {
    console.error(e);
    log('Error al cifrar archivo: ' + e.message, 'error');
    hideLoading();
  }
}

async function handleDecryptFile() {
  const file = document.getElementById('fileDecrypt').files[0];
  const pwd = document.getElementById('pwdDecrypt').value;
  const mode = document.getElementById('fileMode') ? document.getElementById('fileMode').value : 'GCM';
  
  if (!file || !pwd) {
    log('Por favor, selecciona un archivo .aes y la contraseña', 'warning');
    return;
  }
  
  try {
    showLoading(`Descifrando ${file.name} con AES-${mode}...`);
    log(`Iniciando descifrado de ${file.name} (${formatFileSize(file.size)}) con modo ${mode}`);
    
    const ab = await file.arrayBuffer();
    const decBuf = await decryptArrayBuffer(ab, pwd, mode);
    
    // Determinar el tipo MIME basado en la extensión del archivo original
    console.log(`Archivo original: "${file.name}"`);
    
    // Procesar el nombre del archivo de manera más robusta
    let outName;
    // Quitar tanto .aes como .ecb.aes, .cbc.aes, .gcm.aes
    const cleanName = file.name.replace(/\.(ecb|cbc|gcm)\.aes$/i, '').replace(/\.aes$/i, '');
    outName = cleanName || 'descifrado.bin';
    
    console.log(`Nombre procesado: "${outName}"`);
    
    let mimeType = getMimeTypeFromExtension(outName);
    console.log(`MIME type por extensión: "${mimeType}"`);
    
    // Si no se detectó como imagen por extensión, intentar por bytes mágicos
    if (!mimeType.startsWith('image/')) {
      const detectedImageType = detectImageTypeFromBytes(decBuf);
      if (detectedImageType) {
        console.log(`Imagen detectada por bytes mágicos: "${detectedImageType}"`);
        mimeType = detectedImageType;
        
        // Actualizar el nombre del archivo con la extensión correcta si es necesario
        const extensionMap = {
          'image/png': '.png',
          'image/jpeg': '.jpg',
          'image/gif': '.gif',
          'image/webp': '.webp',
          'image/bmp': '.bmp'
        };
        
        if (extensionMap[mimeType] && !outName.toLowerCase().includes('.')) {
          outName += extensionMap[mimeType];
          console.log(`Nombre actualizado con extensión: "${outName}"`);
        }
      }
    }
    
    console.log(`MIME type final: "${mimeType}"`);
    const blob = new Blob([decBuf], { type: mimeType });
    
    // Mostrar vista previa si es imagen
    const tempFile = new File([blob], outName, { type: mimeType });
    console.log(`File object creado:`, {
      name: tempFile.name,
      type: tempFile.type,
      size: tempFile.size
    });
    
    showImagePreview(tempFile, 'previewAreaDecrypted');
    
    // Crear botón de descarga
    const saveDiv = document.getElementById('saveDownload');
    saveDiv.innerHTML = `
      <button class="btn btn-success full-width" onclick="downloadDecryptedFile()" style="margin-top: 15px;">
        <i class="fas fa-download"></i> Descargar ${outName}
      </button>
    `;
    
    // Guardar referencia para descarga
    window.decryptedBlob = blob;
    window.decryptedFilename = outName;
    
    log(`¡Archivo descifrado exitosamente con AES-${mode}!`, 'success');
    hideLoading();
  } catch(e) {
    console.error(e);
    log('Error al descifrar. Verifique la contraseña y el modo: ' + e.message, 'error');
    hideLoading();
  }
}

function downloadDecryptedFile() {
  if (window.decryptedBlob && window.decryptedFilename) {
    downloadBlob(window.decryptedBlob, window.decryptedFilename);
    log(`Descargando ${window.decryptedFilename}`, 'success');
  }
}

/* === HANDLER DE PRUEBAS DE SEGURIDAD === */
async function handleIterationsTest() {
  const btn = document.getElementById('btnIterationsTest');
  const resultsDiv = document.getElementById('iterationResults');
  
  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-sync-alt fa-spin"></i> Ejecutando prueba...';
  
  try {
    log(`Iniciando prueba de ${PBKDF2_ITERS} iteraciones PBKDF2...`, 'warning');
    
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const startTime = performance.now();
    
    await deriveKeyFromPassword('test-password-123', salt);
    
    const endTime = performance.now();
    const duration = (endTime - startTime).toFixed(2);
    
    resultsDiv.style.display = 'block';
    resultsDiv.innerHTML = `
      <h4><i class="fas fa-stopwatch"></i> Resultados de la Prueba</h4>
      <div class="alert alert-info">
        <i class="fas fa-info-circle"></i>
        <div>
          <strong>Tiempo de derivación:</strong> ${duration} ms<br>
          <strong>Iteraciones:</strong> ${PBKDF2_ITERS.toLocaleString()}<br>
          <strong>Análisis:</strong> Un atacante necesitaría este tiempo multiplicado por cada intento de contraseña.
        </div>
      </div>
    `;
    
    log(`Prueba completada en ${duration} ms`, 'success');
  } catch(e) {
    log('Error en la prueba: ' + e.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-stopwatch"></i> Probar Derivación de Clave';
  }
}

/* === INICIALIZACIÓN === */
document.addEventListener('DOMContentLoaded', function() {
  // Inicializar sistemas
  initTabs();
  initPasswordToggles();
  initPasswordStrength();
  initDragAndDrop();
  
  // Event listeners para texto
  document.getElementById('btnEncryptText').addEventListener('click', handleEncryptText);
  document.getElementById('btnDecryptText').addEventListener('click', handleDecryptText);
  document.getElementById('btnCopyResult').addEventListener('click', handleCopyResult);
  
  // Event listeners para archivos
  document.getElementById('fileEncrypt').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
      showFileInfo(file, 'encryptFileInfo');
      showImagePreview(file, 'previewAreaOriginal');
      log(`Archivo seleccionado: ${file.name} (${formatFileSize(file.size)})`);
    }
  });
  
  document.getElementById('fileDecrypt').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
      showFileInfo(file, 'decryptFileInfo');
      document.getElementById('previewAreaDecrypted').innerHTML = '';
      document.getElementById('saveDownload').innerHTML = '';
      log(`Archivo .aes seleccionado: ${file.name} (${formatFileSize(file.size)})`);
    }
  });
  
  document.getElementById('btnEncrypt').addEventListener('click', handleEncryptFile);
  document.getElementById('btnDecrypt').addEventListener('click', handleDecryptFile);
  
  // Event listener para pruebas de seguridad
  document.getElementById('btnIterationsTest').addEventListener('click', handleIterationsTest);
  
  // Sincronizar selectores de modo
  const textModeSelect = document.getElementById('textMode');
  const fileModeSelect = document.getElementById('fileMode');
  
  if (textModeSelect) {
    textModeSelect.addEventListener('change', (e) => {
      const mode = e.target.value;
      if (mode === 'ECB') {
        log('⚠️ Modo ECB seleccionado: Este modo es INSEGURO y solo para demostración educativa', 'warning');
      } else if (mode === 'CBC') {
        log('ℹ️ Modo CBC seleccionado: Más seguro que ECB pero menos que GCM', 'info');
      } else {
        log('✅ Modo GCM seleccionado: El más seguro, recomendado para uso real', 'success');
      }
    });
  }
  
  if (fileModeSelect) {
    fileModeSelect.addEventListener('change', (e) => {
      const mode = e.target.value;
      if (mode === 'ECB') {
        log('🐧 Modo ECB: Perfecto para ver el "efecto pingüino" en imágenes', 'warning');
      } else if (mode === 'CBC') {
        log('📚 Modo CBC: Oculta patrones mejor que ECB', 'info');
      } else {
        log('🔒 Modo GCM: Máxima seguridad, no verás patrones', 'success');
      }
    });
  }
  
  // Teclas de acceso rápido
  document.addEventListener('keydown', (e) => {
    if (e.ctrlKey || e.metaKey) {
      switch(e.key) {
        case 'e':
          e.preventDefault();
          handleEncryptText();
          break;
        case 'd':
          e.preventDefault();
          handleDecryptText();
          break;
      }
    }
  });
  
  log('Sistema AES Cipher Studio inicializado correctamente con soporte para GCM, CBC y ECB', 'success');
});

/* === UTILIDADES ADICIONALES === */
window.downloadDecryptedFile = downloadDecryptedFile;

// Limpiar recursos al cerrar la página
window.addEventListener('beforeunload', () => {
  if (window.decryptedBlob) {
    URL.revokeObjectURL(window.decryptedBlob);
  }
});

// ===== DEMOSTRACIÓN VISUAL DEL "EFECTO PINGÜINO" =====

// Tamaño fijo para la demo (múltiplo de 16 para los bloques AES)
const DEMO_CANVAS_SIZE = 256;

// Referencias a los canvas
let ctxOriginal, ctxECB, ctxGCM;
let originalImageData = null;

// Inicializar la demostración visual cuando cargue la página
document.addEventListener('DOMContentLoaded', () => {
  initVisualDemo();
});

function initVisualDemo() {
  // Obtener referencias a los canvas
  const canvasOriginal = document.getElementById('canvasOriginal');
  const canvasECB = document.getElementById('canvasECB');
  const canvasGCM = document.getElementById('canvasGCM');
  
  if (!canvasOriginal || !canvasECB || !canvasGCM) return;
  
  ctxOriginal = canvasOriginal.getContext('2d');
  ctxECB = canvasECB.getContext('2d');
  ctxGCM = canvasGCM.getContext('2d');
  
  // Configurar el tamaño de los canvas
  [canvasOriginal, canvasECB, canvasGCM].forEach(canvas => {
    canvas.width = DEMO_CANVAS_SIZE;
    canvas.height = DEMO_CANVAS_SIZE;
  });
  
  // Event listeners
  document.getElementById('demoImageInput')?.addEventListener('change', loadDemoImage);
  document.getElementById('runVisualDemo')?.addEventListener('click', runVisualDemo);
}

function loadDemoImage(event) {
  const file = event.target.files[0];
  if (!file) return;
  
  updateDemoStatus('Cargando imagen...');
  
  const reader = new FileReader();
  reader.onload = (e) => {
    const img = new Image();
    img.onload = () => {
      // Dibujar la imagen redimensionada en el canvas original
      ctxOriginal.clearRect(0, 0, DEMO_CANVAS_SIZE, DEMO_CANVAS_SIZE);
      ctxOriginal.drawImage(img, 0, 0, DEMO_CANVAS_SIZE, DEMO_CANVAS_SIZE);
      
      // Guardar los datos de píxeles
      originalImageData = ctxOriginal.getImageData(0, 0, DEMO_CANVAS_SIZE, DEMO_CANVAS_SIZE);
      
      updateDemoStatus('Imagen cargada. Lista para demostración.');
      document.getElementById('runVisualDemo').disabled = false;
    };
    img.src = e.target.result;
  };
  reader.readAsDataURL(file);
}

async function runVisualDemo() {
  if (!originalImageData) {
    updateDemoStatus('Error: Por favor, carga una imagen primero.');
    return;
  }
  
  const password = document.getElementById('demoPassword').value;
  if (!password) {
    updateDemoStatus('Error: Por favor, introduce una contraseña.');
    return;
  }
  
  document.getElementById('runVisualDemo').disabled = true;
  updateDemoStatus('Ejecutando demostración... esto puede tardar un momento.');
  
  try {
    // El buffer de píxeles (RGBA, RGBA, ...)
    const pixelBuffer = originalImageData.data.buffer;
    
    // Ejecutar demos en paralelo
    await Promise.all([
      runECBDemo(pixelBuffer, password),
      runGCMDemo(pixelBuffer, password)
    ]);
    
    updateDemoStatus('¡Demostración completada! Compara los resultados y observa el "efecto pingüino" en ECB.');
    
  } catch (error) {
    console.error('Error en demostración visual:', error);
    updateDemoStatus('Error: ' + error.message);
  } finally {
    document.getElementById('runVisualDemo').disabled = false;
  }
}

// Demostración ECB usando CryptoJS (inseguro - muestra patrones)
async function runECBDemo(pixelBuffer, password) {
  return new Promise((resolve, reject) => {
    try {
      // Asegurar que el buffer tenga el tamaño correcto
      const expectedSize = DEMO_CANVAS_SIZE * DEMO_CANVAS_SIZE * 4; // RGBA
      const actualSize = pixelBuffer.byteLength;
      
      console.log(`ECB Demo - Expected size: ${expectedSize}, Actual size: ${actualSize}`);
      
      // Crear buffer del tamaño correcto
      let processBuffer;
      if (actualSize !== expectedSize) {
        processBuffer = new ArrayBuffer(expectedSize);
        const processView = new Uint8Array(processBuffer);
        const sourceView = new Uint8Array(pixelBuffer);
        processView.set(sourceView.slice(0, Math.min(actualSize, expectedSize)));
      } else {
        processBuffer = pixelBuffer;
      }
      
      // Preparar datos para CryptoJS
      const key = CryptoJS.enc.Utf8.parse(password);
      const dataWA = CryptoJS.lib.WordArray.create(processBuffer);
      
      // Cifrar usando ECB (modo inseguro)
      const encryptedWA = CryptoJS.AES.encrypt(dataWA, key, { 
        mode: CryptoJS.mode.ECB, 
        padding: CryptoJS.pad.NoPadding 
      });
      
      // Convertir resultado a Uint8Array
      const encryptedBytes = cryptoJSToUint8Array(encryptedWA.ciphertext);
      
      // Asegurar que tenemos exactamente el tamaño correcto
      const finalBytes = new Uint8Array(expectedSize);
      finalBytes.set(encryptedBytes.slice(0, expectedSize));
      
      // Mostrar en canvas ECB
      const imageData = ctxECB.createImageData(DEMO_CANVAS_SIZE, DEMO_CANVAS_SIZE);
      imageData.data.set(finalBytes);
      ctxECB.putImageData(imageData, 0, 0);
      
      resolve();
    } catch (error) {
      reject(error);
    }
  });
}

// Demostración GCM usando Web Crypto API (seguro - ruido total)
async function runGCMDemo(pixelBuffer, password) {
  try {
    // Derivar clave usando PBKDF2
    const enc = new TextEncoder();
    const passKey = await crypto.subtle.importKey(
      'raw', 
      enc.encode(password), 
      'PBKDF2', 
      false, 
      ['deriveKey']
    );
    
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await crypto.subtle.deriveKey(
      { 
        name: 'PBKDF2', 
        salt: salt, 
        iterations: 100000, 
        hash: 'SHA-256' 
      },
      passKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );

    // Cifrar con GCM
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptedBuffer = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv }, 
      key, 
      pixelBuffer
    );
    
    // Mostrar en canvas GCM
    const expectedSize = DEMO_CANVAS_SIZE * DEMO_CANVAS_SIZE * 4;
    const encryptedBytes = new Uint8Array(encryptedBuffer);
    
    // Asegurar tamaño correcto
    const finalBytes = new Uint8Array(expectedSize);
    finalBytes.set(encryptedBytes.slice(0, expectedSize));
    
    const imageData = ctxGCM.createImageData(DEMO_CANVAS_SIZE, DEMO_CANVAS_SIZE);
    imageData.data.set(finalBytes);
    ctxGCM.putImageData(imageData, 0, 0);
    
  } catch (error) {
    throw new Error('Error en cifrado GCM: ' + error.message);
  }
}

// Helper para convertir WordArray de CryptoJS a Uint8Array
function cryptoJSToUint8Array(wordArray) {
  const len = wordArray.sigBytes;
  const words = wordArray.words;
  const uint8 = new Uint8Array(len);
  
  for (let i = 0; i < len; i++) {
    const wordIndex = i >>> 2; // i / 4
    const byteIndex = i % 4;
    
    // Verificar bounds
    if (wordIndex >= words.length) {
      console.warn(`Word index ${wordIndex} out of bounds, words length: ${words.length}`);
      break;
    }
    
    const word = words[wordIndex];
    uint8[i] = (word >>> (24 - byteIndex * 8)) & 0xff;
  }
  
  return uint8;
}

// Actualizar estado de la demostración
function updateDemoStatus(message) {
  const statusEl = document.getElementById('demoStatus');
  if (statusEl) {
    statusEl.textContent = message;
    statusEl.style.display = message ? 'block' : 'none';
  }
}

// ===== PROCESO DETALLADO DE CIFRADO =====

// Mostrar el proceso paso a paso
function showEncryptionProcess() {
  const processSection = document.getElementById('processDetails');
  if (processSection) {
    processSection.style.display = 'block';
    processSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

// Actualizar paso 1: Salt
function updateStep1(saltBytes) {
  const saltHex = Array.from(saltBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  document.getElementById('saltValue').textContent = `Salt (16 bytes): ${saltHex}`;
}

// Actualizar paso 2: Derivación de clave
function updateStep2(password, saltBytes, derivedKey) {
  document.getElementById('passwordInfo').textContent = password.length > 20 ? password.substring(0, 20) + '...' : password;
  const saltHex = Array.from(saltBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  document.getElementById('saltInfo').textContent = saltHex.substring(0, 32) + '...';
  
  // Mostrar clave derivada (solo una parte por seguridad)
  crypto.subtle.exportKey('raw', derivedKey).then(keyBuffer => {
    const keyBytes = new Uint8Array(keyBuffer);
    const keyHex = Array.from(keyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    document.getElementById('keyValue').textContent = `Clave AES-256: ${keyHex.substring(0, 32)}... (256 bits total)`;
  }).catch(() => {
    document.getElementById('keyValue').textContent = 'Clave AES-256: [Clave derivada exitosamente - 256 bits]';
  });
}

// Actualizar paso 3: IV/Nonce
function updateStep3(ivBytes, mode) {
  const ivHex = Array.from(ivBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  document.getElementById('ivValue').textContent = `${mode} IV: ${ivHex}`;
  
  const descriptions = {
    'GCM': 'Vector de inicialización (nonce) de 12 bytes para AES-GCM',
    'CBC': 'Vector de inicialización de 16 bytes para AES-CBC',
    'ECB': 'ECB no utiliza IV (una de sus debilidades de seguridad)'
  };
  
  const purposes = {
    'GCM': 'Garantizar unicidad y prevenir ataques de repetición',
    'CBC': 'Encadenar bloques y añadir aleatoriedad al cifrado',
    'ECB': 'N/A - ECB no usa IV'
  };
  
  const lengths = {
    'GCM': '12 bytes (96 bits)',
    'CBC': '16 bytes (128 bits)',
    'ECB': 'N/A'
  };
  
  document.getElementById('ivDescription').textContent = descriptions[mode] || descriptions['GCM'];
  document.getElementById('ivLength').textContent = lengths[mode] || lengths['GCM'];
  document.getElementById('ivPurpose').textContent = purposes[mode] || purposes['GCM'];
}

// Actualizar paso 4: Cifrado
function updateStep4(plainText, mode, cipherBytes) {
  const cipherHex = Array.from(cipherBytes.slice(0, 32)).map(b => b.toString(16).padStart(2, '0')).join('');
  document.getElementById('cipherValue').textContent = `Datos cifrados: ${cipherHex}... (${cipherBytes.length} bytes total)`;
  
  document.getElementById('algorithmInfo').textContent = 'AES (Advanced Encryption Standard)';
  document.getElementById('modeInfo').textContent = `${mode} (${getModeDescription(mode)})`;
  document.getElementById('originalTextInfo').textContent = plainText.length > 50 ? plainText.substring(0, 50) + '...' : plainText;
  document.getElementById('inputBytesInfo').textContent = `${new TextEncoder().encode(plainText).length} bytes`;
}

// Actualizar paso 5: Formato final
function updateStep5(finalBase64, mode, totalSize) {
  const preview = finalBase64.length > 100 ? finalBase64.substring(0, 100) + '...' : finalBase64;
  document.getElementById('finalValue').textContent = `Base64: ${preview}`;
  
  const structures = {
    'GCM': 'Salt (16 bytes) + IV (12 bytes) + Datos cifrados + Tag de autenticación',
    'CBC': 'Salt (16 bytes) + IV (16 bytes) + Datos cifrados con padding',
    'ECB': 'Salt (16 bytes) + Datos cifrados con padding'
  };
  
  document.getElementById('structureInfo').textContent = structures[mode] || structures['GCM'];
  document.getElementById('totalSizeInfo').textContent = `${totalSize} bytes (${finalBase64.length} caracteres Base64)`;
}

// Obtener descripción del modo
function getModeDescription(mode) {
  const descriptions = {
    'GCM': 'Galois/Counter Mode - Cifrado autenticado',
    'CBC': 'Cipher Block Chaining - Cifrado por bloques encadenados',
    'ECB': 'Electronic Code Book - Cifrado por bloques independientes'
  };
  return descriptions[mode] || descriptions['GCM'];
}

// Animar los pasos
function animateStep(stepNumber) {
  const step = document.getElementById(`step${stepNumber}`);
  if (step) {
    step.classList.add('step-active');
    setTimeout(() => {
      step.classList.remove('step-active');
    }, 1500);
  }
}