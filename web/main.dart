import 'dart:js_interop';
import 'dart:js_interop_unsafe';
import 'dart:typed_data';

import 'package:dvault/src/vfs/http_lockbox.dart';
import 'package:dvault/src/lockbox/lock_box.dart';
import 'package:dvault/src/vfs/opfs_lockbox.dart';
import 'package:web/web.dart' as web;

LockBox? currentVault;
bool isReadOnly = false;

void main() {
  print('DVault Browser Demo initializing...');

  checkBrowserSupport();
  setupEventListeners();
  updateStorageInfo();
}

void checkBrowserSupport() {
  final supportInfo = web.document.getElementById('support-info')!;
  supportInfo.innerHTML = ''.toJS;

  // Check OPFS
  bool opfsSupported = false;
  try {
    final storage = web.window.navigator.storage;
    opfsSupported = (storage as JSObject).has('getDirectory');
  } catch (e) {
    opfsSupported = false;
  }
  supportInfo.appendChild(
    _createSupportItem('OPFS (Writable Vaults)', opfsSupported),
  );

  // Check Fetch API
  bool fetchSupported = false;
  try {
    fetchSupported = (web.window as JSObject).has('fetch');
  } catch (e) {
    fetchSupported = false;
  }
  supportInfo.appendChild(
    _createSupportItem('HTTP Fetch (Remote Vaults)', fetchSupported),
  );

  // Check Crypto API
  bool cryptoSupported = false;
  try {
    web.window.crypto;
    cryptoSupported = true;
  } catch (e) {
    cryptoSupported = false;
  }
  supportInfo.appendChild(
    _createSupportItem('Web Crypto API', cryptoSupported),
  );

  // Check File System Access API
  bool fileSystemSupported = false;
  try {
    web.window.navigator.storage;
    fileSystemSupported = true;
  } catch (e) {
    fileSystemSupported = false;
  }
  supportInfo.appendChild(
    _createSupportItem('File System Access API', fileSystemSupported),
  );
}

web.HTMLElement _createSupportItem(String feature, bool supported) {
  final div = web.document.createElement('div') as web.HTMLDivElement;
  div.className =
      supported ? 'support-item supported' : 'support-item not-supported';
  div.textContent = '${supported ? "✓" : "✗"} $feature';
  return div;
}

void setupEventListeners() {
  final createBtn =
      web.document.getElementById('create-vault-btn') as web.HTMLButtonElement;
  createBtn.addEventListener(
    'click',
    ((web.Event event) {
      createVault();
    }).toJS,
  );

  final openBtn =
      web.document.getElementById('open-vault-btn') as web.HTMLButtonElement;
  openBtn.addEventListener(
    'click',
    ((web.Event event) {
      openVault();
    }).toJS,
  );

  final openHttpBtn =
      web.document.getElementById('open-http-btn') as web.HTMLButtonElement;
  openHttpBtn.addEventListener(
    'click',
    ((web.Event event) {
      openHttpVault();
    }).toJS,
  );

  final addFileBtn =
      web.document.getElementById('add-file-btn') as web.HTMLButtonElement;
  addFileBtn.addEventListener(
    'click',
    ((web.Event event) {
      addFile();
    }).toJS,
  );

  final setEnvBtn =
      web.document.getElementById('set-env-btn') as web.HTMLButtonElement;
  setEnvBtn.addEventListener(
    'click',
    ((web.Event event) {
      setEnvVar();
    }).toJS,
  );

  final listEnvBtn =
      web.document.getElementById('list-env-btn') as web.HTMLButtonElement;
  listEnvBtn.addEventListener(
    'click',
    ((web.Event event) {
      listEnvVars();
    }).toJS,
  );

  final listFilesBtn =
      web.document.getElementById('list-files-btn') as web.HTMLButtonElement;
  listFilesBtn.addEventListener(
    'click',
    ((web.Event event) {
      listFiles();
    }).toJS,
  );
}

Future<void> createVault() async {
  try {
    final name =
        (web.document.getElementById('vault-name') as web.HTMLInputElement)
            .value;
    final password =
        (web.document.getElementById('vault-password') as web.HTMLInputElement)
            .value;

    log('Creating vault "$name"...', 'info');

    currentVault = await OPFSLockbox.open(
      vaultName: name,
      password: password,
      create: true,
    );

    isReadOnly = false;
    log('✓ Vault created successfully!', 'success');
    showVaultControls();
    updateStorageInfo();
  } catch (e) {
    log('✗ Error creating vault: $e', 'error');
  }
}

Future<void> openVault() async {
  try {
    final name =
        (web.document.getElementById('vault-name') as web.HTMLInputElement)
            .value;
    final password =
        (web.document.getElementById('vault-password') as web.HTMLInputElement)
            .value;

    log('Opening vault "$name"...', 'info');

    currentVault = await OPFSLockbox.open(vaultName: name, password: password);

    isReadOnly = false;
    log('✓ Vault opened successfully!', 'success');
    showVaultControls();
    await listFiles();
  } catch (e) {
    log('✗ Error opening vault: $e', 'error');
  }
}

Future<void> openHttpVault() async {
  try {
    final url =
        (web.document.getElementById('vault-url') as web.HTMLInputElement)
            .value;
    final password =
        (web.document.getElementById('http-password') as web.HTMLInputElement)
            .value;

    if (url.isEmpty) {
      log('✗ Please enter a vault URL', 'error');
      return;
    }

    log('Opening remote vault...', 'info');

    currentVault = await HTTPLockbox.open(url: url, password: password);

    isReadOnly = true;
    log('✓ Remote vault opened (read-only)!', 'success');
    log('ℹ Note: HTTP vaults are read-only', 'info');
    showVaultControls();
    await listFiles();
  } catch (e) {
    log('✗ Error opening remote vault: $e', 'error');
    log('  Make sure the server supports CORS and Range requests', 'info');
  }
}

Future<void> addFile() async {
  if (currentVault == null) {
    log('✗ No vault open', 'error');
    return;
  }

  if (isReadOnly) {
    log('✗ Cannot add files to read-only vault', 'error');
    return;
  }

  try {
    final path =
        (web.document.getElementById('file-path') as web.HTMLInputElement)
            .value;
    final content =
        (web.document.getElementById('file-content') as web.HTMLTextAreaElement)
            .value;

    if (path.isEmpty) {
      log('✗ Please enter a file path', 'error');
      return;
    }

    log('Adding file "$path"...', 'info');

    final data = Uint8List.fromList(content.codeUnits);
    await currentVault!.write(path, data);

    log('✓ File added successfully!', 'success');
    await listFiles();
  } catch (e) {
    log('✗ Error adding file: $e', 'error');
  }
}

Future<void> setEnvVar() async {
  if (currentVault == null) {
    log('✗ No vault open', 'error');
    return;
  }

  if (isReadOnly) {
    log('✗ Cannot set env vars in read-only vault', 'error');
    return;
  }

  try {
    final key =
        (web.document.getElementById('env-key') as web.HTMLInputElement).value;
    final value =
        (web.document.getElementById('env-value') as web.HTMLInputElement)
            .value;

    if (key.isEmpty) {
      log('✗ Please enter an environment variable key', 'error');
      return;
    }

    log('Setting $key=$value...', 'info');

    await currentVault!.setEnv(key, value);

    log('✓ Environment variable set!', 'success');
  } catch (e) {
    log('✗ Error setting env var: $e', 'error');
  }
}

Future<void> listEnvVars() async {
  if (currentVault == null) {
    log('✗ No vault open', 'error');
    return;
  }

  try {
    final envVars = currentVault!.listEnv();

    if (envVars.isEmpty) {
      log('No environment variables set', 'info');
    } else {
      log('Environment Variables:', 'info');
      for (final entry in envVars.entries) {
        log('  ${entry.key} = ${entry.value}', 'info');
      }
    }
  } catch (e) {
    log('✗ Error listing env vars: $e', 'error');
  }
}

Future<void> listFiles() async {
  if (currentVault == null) {
    log('✗ No vault open', 'error');
    return;
  }

  try {
    final files = currentVault!.list('/', recursive: true);

    final fileListDiv = web.document.getElementById('file-list')!;
    fileListDiv.innerHTML = ''.toJS;

    if (files.isEmpty) {
      fileListDiv.textContent = 'No files in vault';
    } else {
      log('Files in vault: ${files.length}', 'info');

      for (final file in files) {
        final fileItem =
            web.document.createElement('div') as web.HTMLDivElement;
        fileItem.className = 'file-item';
        fileItem.textContent = '📄 $file';
        fileItem.addEventListener(
          'click',
          ((web.Event event) {
            readFile(file);
          }).toJS,
        );
        fileListDiv.appendChild(fileItem);
      }
    }
  } catch (e) {
    log('✗ Error listing files: $e', 'error');
  }
}

Future<void> readFile(String path) async {
  if (currentVault == null) return;

  try {
    log('Reading "$path"...', 'info');

    final data = await currentVault!.read(path);
    final content = String.fromCharCodes(data);

    log('Content of "$path":', 'info');
    log(content, 'info');
  } catch (e) {
    log('✗ Error reading file: $e', 'error');
  }
}

void showVaultControls() {
  final controls =
      web.document.getElementById('vault-controls') as web.HTMLElement;
  controls.style.display = 'block';
}

void log(String message, [String type = 'info']) {
  final output = web.document.getElementById('output')!;
  final line = web.document.createElement('div') as web.HTMLDivElement;
  line.className = 'output-line $type';
  line.textContent = message;
  output.appendChild(line);
  output.scrollTop = output.scrollHeight.toDouble();
}

Future<void> updateStorageInfo() async {
  if (!OPFSLockbox.isSupported()) return;

  try {
    final estimate = await OPFSLockbox.getStorageEstimate();
    final usage = estimate['usage']!;
    final quota = estimate['quota']!;
    final usedMB = (usage / 1024 / 1024).toStringAsFixed(2);
    final quotaMB = (quota / 1024 / 1024).toStringAsFixed(2);
    final percent = ((usage / quota) * 100).toStringAsFixed(1);

    final storageInfo = web.document.getElementById('storage-info')!;
    storageInfo.textContent =
        'Storage: $usedMB MB / $quotaMB MB ($percent% used)';
  } catch (e) {
    print('Error getting storage info: $e');
  }
}
