import io
import hashlib
import base64
import paramiko
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def generate_key_pair(key_type='ed25519', bits=4096, passphrase=None):
    if key_type == 'rsa':
        key = paramiko.RSAKey.generate(bits)
        actual_bits = bits
    elif key_type == 'ecdsa':
        key = paramiko.ECDSAKey.generate(bits=521)
        actual_bits = 521
    elif key_type == 'ed25519':
        raw_key = Ed25519PrivateKey.generate()
        enc_algo = serialization.BestAvailableEncryption(passphrase.encode()) if passphrase else serialization.NoEncryption()
        
        private_pem = raw_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=enc_algo
        ).decode('utf-8')
        
        public_openssh = raw_key.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ).decode('utf-8')
        
        key = paramiko.Ed25519Key.from_private_key(io.StringIO(private_pem), password=passphrase.encode() if passphrase else None)
        actual_bits = 256
    else:
        raise ValueError(f"Unsupported key type: {key_type}")

    if key_type != 'ed25519':
        priv_buf = io.StringIO()
        key.write_private_key(priv_buf, password=passphrase.encode() if passphrase else None)
        private_pem = priv_buf.getvalue()
        public_openssh = f"{key.get_name()} {key.get_base64()}"

    key_data = key.asbytes()
    digest = hashlib.sha256(key_data).digest()
    fingerprint = "SHA256:" + base64.b64encode(digest).decode().rstrip('=')
    
    return private_pem, public_openssh, fingerprint, actual_bits

def deploy_key_to_host(host, public_key_line):
    transport = paramiko.Transport((host.hostname, host.port))
    transport.set_keepalive(30)

    if host.auth_type == 'password':
        transport.connect(username=host.username, password=host.password)
    else:
        pkey = None
        pp = host.passphrase or None
        for kc in [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey]:
            try:
                pkey = kc.from_private_key(io.StringIO(host.ssh_key), password=pp)
                break
            except Exception:
                continue
        if pkey is None:
            raise ValueError("Unable to connect to host: SSH key invalid")
        transport.connect(username=host.username, pkey=pkey)

    try:
        sftp = paramiko.SFTPClient.from_transport(transport)

        ssh_dir = f'/home/{host.username}/.ssh'
        if host.username == 'root':
            ssh_dir = '/root/.ssh'
        try:
            sftp.stat(ssh_dir)
        except FileNotFoundError:
            sftp.mkdir(ssh_dir, mode=0o700)

        auth_keys_path = f'{ssh_dir}/authorized_keys'

        existing = ''
        try:
            with sftp.open(auth_keys_path, 'r') as f:
                existing = f.read().decode('utf-8', errors='replace')
        except FileNotFoundError:
            pass

        pub_key_data = public_key_line.strip()
        if pub_key_data in existing:
            sftp.close()
            return {'status': 'already_deployed', 'message': 'The key is already installed on the host.'}

        new_content = existing.rstrip('\n') + '\n' + pub_key_data + '\n' if existing.strip() else pub_key_data + '\n'
        with sftp.open(auth_keys_path, 'w') as f:
            f.write(new_content.encode('utf-8'))

        sftp.chmod(auth_keys_path, 0o600)
        sftp.close()

        return {'status': 'deployed', 'message': 'Key successfully installed on the host'}

    finally:
        transport.close()


def remove_key_from_host(host, public_key_line):
    transport = paramiko.Transport((host.hostname, host.port))
    transport.set_keepalive(30)

    if host.auth_type == 'password':
        transport.connect(username=host.username, password=host.password)
    else:
        pkey = None
        pp = host.passphrase or None
        for kc in [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey]:
            try:
                pkey = kc.from_private_key(io.StringIO(host.ssh_key), password=pp)
                break
            except Exception:
                continue
        if pkey is None:
            raise ValueError("Unable to connect to host")
        transport.connect(username=host.username, pkey=pkey)

    try:
        sftp = paramiko.SFTPClient.from_transport(transport)

        ssh_dir = f'/home/{host.username}/.ssh'
        if host.username == 'root':
            ssh_dir = '/root/.ssh'
        auth_keys_path = f'{ssh_dir}/authorized_keys'

        try:
            with sftp.open(auth_keys_path, 'r') as f:
                lines = f.read().decode('utf-8', errors='replace').splitlines()
        except FileNotFoundError:
            sftp.close()
            return {'status': 'not_found', 'message': 'authorized_keys not found'}

        pub_key_data = public_key_line.strip()
        new_lines = [l for l in lines if l.strip() and pub_key_data not in l]

        with sftp.open(auth_keys_path, 'w') as f:
            f.write(('\n'.join(new_lines) + '\n').encode('utf-8'))

        sftp.close()
        return {'status': 'removed', 'message': 'Key removed from host'}

    finally:
        transport.close()