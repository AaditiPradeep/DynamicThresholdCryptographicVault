from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, join_room
import hashlib
import time
import os

# --- Cryptographic Imports ---
from vault.pedersen_vss import PedersenVSS
from utils.verification import batch_verify_shares
from vault.dynamic_vault import DynamicThresholdVault
from core.group_params import Q
from main import participant_verify_dealer

app = Flask(__name__)
app.config['SECRET_KEY'] = 'crypto_vault_secure'
socketio = SocketIO(app, cors_allowed_origins="*")

vault_session = {
    "shares": [],
    "commitments": [],
    "threshold": 0,
    "received_shares": {},
    "active_pids": set(),
    "vault": None        # ← dynamic vault object
}

import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from core.group_params import Q


def encrypt_file(file_bytes):

    key = secrets.token_bytes(32)   # AES-256 key

    nonce = secrets.token_bytes(12)

    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(nonce, file_bytes, None)

    secret = int.from_bytes(key, "big")   # ❗ REMOVE mod Q

    return {
        "secret": secret,
        "ciphertext": ciphertext,
        "nonce": nonce
    }


def decrypt_file(ciphertext, key, nonce):
    """
    Decrypt ciphertext using AES key.
    """

    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext

def derive_secret_from_bytes(file_bytes):

    key = hashlib.sha256(file_bytes).digest()

    secret = int.from_bytes(key, "big")

    nonce = secrets.token_bytes(12)

    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(nonce, file_bytes, None)

    return {
        "secret": secret,
        "ciphertext": ciphertext,
        "nonce": nonce
    }

def secret_to_key(secret):
    """
    Convert reconstructed secret integer back to AES key
    """

    key = int(secret).to_bytes(32, "big")

    return key

def derive_secret_from_input(user_input):
    """
    If numeric input → use directly
    Otherwise treat input as file data
    """

    try:
        return {"secret": int(user_input) % Q}
    except (ValueError, TypeError):
        return derive_secret_from_bytes(str(user_input).encode()) 

@app.route('/')
def index(): return render_template('index.html')

@app.route('/dealer')
def dealer_view(): return render_template('dealer.html')

@app.route('/participant')
def participant_view(): return render_template('participant.html')

@socketio.on('register_participant')
def handle_registration(data):
    pid = int(data['pid'])
    join_room(f"room_p_{pid}")
    vault_session["active_pids"].add(pid)
    emit('logs', {'msg': f"Network Node P{pid} is ONLINE."}, broadcast=True)

@socketio.on('start_protocol')
def handle_protocol_start(data):

    n = int(data['n'])
    t = int(data['threshold'])

    if len(vault_session["active_pids"]) < n:
        emit('logs', {
            'msg': f"❌ ERROR: Only {len(vault_session['active_pids'])}/{n} nodes active."
        }, broadcast=True)
        return


    # -------- Derive secret from file or input --------

    if 'file_bytes' in data:

        result = derive_secret_from_bytes(data['file_bytes'])

        secret = result["secret"]
        ciphertext = result["ciphertext"]
        nonce = result["nonce"]

        emit('logs', {
            'msg': "Vault: File encrypted with AES. Key protected using Pedersen VSS."
        }, broadcast=True)

    else:

        result = derive_secret_from_input(data.get('secret', '0'))

        secret = result["secret"]
        ciphertext = None
        nonce = None

        emit('logs', {
            'msg': "Vault: Secret derived from manual input."
        }, broadcast=True)


    # -------- Run Pedersen VSS --------

    vss = PedersenVSS(secret, t, n)

    shares = vss.generate_all_shares()
    commitments = vss.get_public_commitments()


    # -------- Create Dynamic Vault --------

    vault = DynamicThresholdVault(
        secret,
        vss.r_coeffs[0],
        shares,
        commitments,
        t,
        n
    )


    # -------- Store session data --------

    vault_session.update({
        "shares": shares,
        "commitments": commitments,
        "threshold": t,
        "received_shares": {},
        "vault": vault,

        # AES storage
        "ciphertext": ciphertext,
        "nonce": nonce
    })


    # -------- Dealer verification --------

    logs, cheating = participant_verify_dealer(shares, commitments)

    for log_entry in logs:
        emit('logs', {'msg': log_entry}, broadcast=True)


    # -------- Dispatch shares --------

    if not cheating:

        for pid, s_i, r_i in shares:

            emit('receive_private_share', {
                's_i': str(s_i),
                'r_i': str(r_i),
                'commitments': [str(c) for c in commitments]
            }, room=f"room_p_{pid}")


        emit('logs', {
            'msg': "✅ Shares dispatched. Awaiting Dealer pull signal..."
        }, broadcast=True)

@socketio.on('start_malicious_protocol')
def handle_malicious_start(data):
    n, t = int(data['n']), int(data['threshold'])
    if len(vault_session["active_pids"]) < n:
        emit('logs', {'msg': f"❌ ERROR: Connect {n} nodes first."}, broadcast=True)
        return

    if 'file_bytes' in data:
        secret = derive_secret_from_bytes(data['file_bytes'])['secret']
    else:
        secret = derive_secret_from_input(data.get('secret', '0'))['secret']

    vss = PedersenVSS(secret, t, n)
    shares = vss.generate_all_shares()
    commitments = vss.get_public_commitments()

    # --- SIMULATE MALICE ---
    p_id, s_i, r_i = shares[0]
    shares[0] = (p_id, s_i + 1337, r_i) 
    emit('logs', {'msg': f"⚠️ MALICIOUS ACTION: Corrupting share for P{p_id} (Dealer Cheating)..."}, broadcast=True)
    
    # FIXED: Removed 'broadcast=True' because socketio.emit broadcasts by default
    socketio.emit('dealer_malicious_alert', {'target_pid': p_id})
    # -----------------------

    vault_session.update({
        "shares": shares, "commitments": commitments, 
        "threshold": t, "received_shares": {}
    })

    logs, cheating = participant_verify_dealer(shares, commitments)
    for log_entry in logs: emit('logs', {'msg': log_entry}, broadcast=True)

    if cheating:
        emit('logs', {'msg': "🚨 PROTOCOL HALTED: Participants detected Dealer fraud!"}, broadcast=True)
    else:
        for pid, s_i, r_i in shares:
            emit('receive_private_share', {
                's_i': str(s_i), 'r_i': str(r_i), 
                'commitments': [str(c) for c in commitments]
            }, room=f"room_p_{pid}")

@socketio.on('request_shares_from_all')
def handle_collection_trigger():
    vault_session["received_shares"] = {} 
    emit('logs', {'msg': "📢 Dealer: Triggering Batch Collection..."}, broadcast=True)
    emit('request_your_share', broadcast=True)

@socketio.on('adjust_threshold')
def handle_threshold_adjustment(data):
    new_t = int(data['threshold'])

    vault = vault_session.get("vault")

    if vault is None:
        emit('logs', {'msg': "❌ Vault not initialized"}, broadcast=True)
        return

    try:
        vault.adjust_threshold(new_t, reason="live adjustment")

        vault_session["shares"] = vault.shares
        vault_session["commitments"] = vault.commitments
        vault_session["threshold"] = new_t

        for pid, s_i, r_i in vault.shares:
            emit('receive_private_share', {
                's_i': str(s_i),
                'r_i': str(r_i),
                'commitments': [str(c) for c in vault.commitments]
            }, room=f"room_p_{pid}")

        emit('logs', {
            'msg': f"🔁 Dynamic threshold updated → t={new_t}"
        }, broadcast=True)

    except Exception as e:
        emit('logs', {'msg': f"❌ Threshold update failed: {str(e)}"}, broadcast=True)

@socketio.on('submit_for_reconstruction')
def handle_share_submission(data):
    pid = int(data['pid'])
    # Store the incoming share in the session buffer
    vault_session["received_shares"][pid] = (int(data['s_i']), int(data['r_i']))
    
    current_count = len(vault_session["received_shares"])
    total_expected = len(vault_session["active_pids"]) # Use active_pids instead of threshold
    
    # Logic only starts once the LAST expected participant has checked in
    if current_count == total_expected:
        share_list = [(p, s[0], s[1]) for p, s in vault_session["received_shares"].items()]
        commitments = vault_session["commitments"]
        threshold = vault_session["threshold"]
        needed = threshold + 1
        
        emit('logs', {'msg': f"🏁 All {total_expected} shares collected. Starting Batch Analysis..."}, broadcast=True)
        emit('logs', {'msg': "--- Running Verification Benchmarks ---"}, broadcast=True)

        # 1. Benchmark: Individual Verification
        start_norm = time.time()
        for p, s, r in share_list:
            PedersenVSS.verify_share_static(p, s, r, commitments)
        norm_time = time.time() - start_norm
        emit('logs', {'msg': f"Individual Time: {norm_time:.6f}s"}, broadcast=True)

        # 2. Benchmark: Batch Verification
        start_batch = time.time()
        is_valid, _ = batch_verify_shares(share_list, commitments)
        batch_time = time.time() - start_batch
        emit('logs', {'msg': f"Batch Time: {batch_time:.6f}s"}, broadcast=True)
        
        if batch_time > 0:
            emit('logs', {'msg': f"🚀 Speedup: {norm_time / batch_time:.2f}x faster"}, broadcast=True)

        # 3. Filtering & Fallback
        valid_shares = []
        if not is_valid:
            emit('logs', {'msg': "❌ Batch Failure! Identifying malicious inputs..."}, broadcast=True)
            for p, s, r in share_list:
                if PedersenVSS.verify_share_static(p, s, r, commitments):
                    valid_shares.append((p, s, r))
                else:
                    emit('logs', {'msg': f"🚨 MALICIOUS NODE DETECTED: Participant {p}"}, broadcast=True)
        else:
            valid_shares = share_list

        # 4. Final Reconstruction Attempt
        # Check if the number of VALID shares meets the threshold (t+1)
        if len(valid_shares) >= needed:

            secret = PedersenVSS.reconstruct_secret(valid_shares, commitments, threshold)

            emit('logs', {'msg': f"✅ SUCCESS. Reconstructed Secret: {secret}"}, broadcast=True)

            # -------- AES KEY RECOVERY --------

            try:

                key = int(secret).to_bytes(32, "big")

                ciphertext = vault_session.get("ciphertext")
                nonce = vault_session.get("nonce")

                if ciphertext and nonce:

                    plaintext = decrypt_file(ciphertext, key, nonce)

                    with open("decrypted_file.txt", "wb") as f:
                        f.write(plaintext)

                    emit('logs', {
                        'msg': "📂 Vault file decrypted successfully → saved as decrypted_file.txt"
                    }, broadcast=True)

                else:

                    emit('logs', {
                        'msg': "ℹ No encrypted file stored in vault session."
                    }, broadcast=True)

            except Exception as e:

                emit('logs', {
                    'msg': f"❌ Decryption error: {str(e)}"
                }, broadcast=True)
    else:
        # Optional: Log progress while waiting for others
        emit('logs', {'msg': f"📥 Received P{pid} ({current_count}/{total_expected})"}, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)