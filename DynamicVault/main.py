from core.group_params import Q
from vault.pedersen_vss import PedersenVSS
from utils.verification import batch_verify_shares
from vault.dynamic_vault import DynamicThresholdVault
import os
import hashlib
import time
import sys

# -----------------------------
# SAVE SHARES
# -----------------------------
def save_shares_to_files(shares, folder):
    os.makedirs(folder, exist_ok=True)

    for pid, s_i, r_i in shares:
        filename = os.path.join(folder, f"share_{pid}.txt")

        with open(filename, "w") as f:
            f.write(f"Participant ID: {pid}\n")
            f.write(f"Secret Share: {s_i}\n")
            f.write(f"Random Share: {r_i}\n")

        print(f"Share for participant {pid} saved to {filename}")


# -----------------------------
# PARTICIPANTS VERIFY DEALER
# -----------------------------
def participant_verify_dealer(shares, commitments):

    logs = []
    cheating_detected = False

    print("\n=== Participants Verifying Dealer ===\n")
    # simulate malicious dealer
    #shares[2] = (shares[2][0], shares[2][1] + 1, shares[2][2])

    for pid, s_i, r_i in shares:

        valid = PedersenVSS.verify_share_static(pid, s_i, r_i, commitments)

        if valid:

            message = f"Participant {pid} verified dealer share → VALID"

            print(message)          # prints in VSCode terminal
            logs.append(message)    # sends to UI

        else:

            message = f"Participant {pid} detected cheating dealer!"

            print(message)          # prints in VSCode terminal
            logs.append(message)    # sends to UI

            cheating_detected = True

    if cheating_detected:

        termination_msg = "⚠️ Dealer verification FAILED. Terminating protocol."

        print("\n" + termination_msg)
        logs.append(termination_msg)

    else:

        success_msg = "Dealer verification successful. Shares distributed."

        print("\n" + success_msg)
        logs.append(success_msg)

    return logs, cheating_detected

def load_config(config_file):
    """Load n, threshold, and secret from vault_config.txt."""
    with open(config_file, "r") as f:
        lines = f.readlines()
    n = int(lines[0].split(":")[1])
    threshold = int(lines[1].split(":")[1])
    secret = int(lines[2].split(":")[1])
    return n, threshold, secret

# -----------------------------
# RECONSTRUCTION + BENCHMARK
# -----------------------------
def reconstruct_from_files(share_folder, commitments_file, threshold):

    logs = []

    ids = input("Enter participant IDs (comma separated): ")
    ids = [int(x.strip()) for x in ids.split(",")]

    # check duplicates
    if len(ids) != len(set(ids)):
        print("❌ Duplicate participant IDs detected.")
        return None

    # check threshold requirement
    if len(ids) < threshold + 1:
        print(f"❌ Need at least {threshold+1} unique shares.")
        return None

    shares = load_selected_shares(share_folder, ids)
    commitments = load_commitments(commitments_file)

    logs.append("Loaded Shares:")
    print("\nLoaded Shares:")

    for s in shares:
        print(s)
        logs.append(str(s))

    logs.append("=== Verification Performance Comparison ===")
    print("\n=== Verification Performance Comparison ===")

    # -----------------------------
    # NORMAL VERIFICATION
    # -----------------------------
    start = time.time()

    for pid, s_i, r_i in shares:

        valid = PedersenVSS.verify_share_static(pid, s_i, r_i, commitments)

        msg = f"Checking Share {pid} → {'VALID' if valid else 'INVALID'}"

        print(msg)
        logs.append(msg)

    end = time.time()
    original_time = end - start

    time_msg = f"Original verification time: {original_time:.6f} seconds"

    print(time_msg)
    logs.append(time_msg)

    # -----------------------------
    # BATCH VERIFICATION
    # -----------------------------
    start = time.time()
    is_valid, invalid_ids = batch_verify_shares(shares, commitments)

    end = time.time()
    batch_time = end - start

    if not is_valid:
        print("Batch verification detected inconsistency. Running individual checks...")
        invalid_ids = []

        for pid, s_i, r_i in shares:
            if not PedersenVSS.verify_share_static(pid, s_i, r_i, commitments):
                invalid_ids.append(pid)

    batch_msg = f"Batch verification time: {batch_time:.6f} seconds"

    print(batch_msg)
    logs.append(batch_msg)

    if batch_time > 0:

        speed_msg = f"Speed improvement: {original_time/batch_time:.2f}x faster"

        print(speed_msg)
        logs.append(speed_msg)

    # -----------------------------
    # VALID SHARE FILTERING
    # -----------------------------
    valid_shares = []

    for pid, s_i, r_i in shares:

        if pid in invalid_ids:

            msg = f"❌ Share from Participant {pid} is INVALID"

            print(msg)
            logs.append(msg)

        else:

            msg = f"✅ Share from Participant {pid} is VALID"

            print(msg)
            logs.append(msg)

            valid_shares.append((pid, s_i, r_i))

    if len(valid_shares) < threshold + 1:

        msg = "❌ Not enough valid shares to reconstruct the secret."

        print(msg)
        logs.append(msg)

        return None, logs

    # -----------------------------
    # SECRET RECONSTRUCTION
    # -----------------------------
    secret = PedersenVSS.reconstruct_secret(valid_shares, commitments, threshold)

    success_msg = f"✅ Secret reconstructed successfully: {secret}"

    print(success_msg)
    logs.append(success_msg)

    return secret, logs


# -----------------------------
# FILE HELPERS
# -----------------------------
def load_commitments(file_path):

    commitments = []

    with open(file_path, "r") as f:
        for line in f:
            value = int(line.split(":")[1])
            commitments.append(value)

    return commitments


def load_selected_shares(folder_path, participant_ids):

    shares = []

    for pid in participant_ids:

        filename = os.path.join(folder_path, f"share_{pid}.txt")

        with open(filename, "r") as f:
            lines = f.readlines()

            s_i = int(lines[1].split(":")[1])
            r_i = int(lines[2].split(":")[1])

            shares.append((pid, s_i, r_i))

    return shares


def secret_from_file(file_path):

    with open(file_path, "rb") as f:
        data = f.read()

    digest = hashlib.sha256(data).digest()

    secret = int.from_bytes(digest, "big") % Q

    if secret == 0:
        secret = 1

    return secret


def load_threshold(config_file):

    with open(config_file, "r") as f:
        lines = f.readlines()

    threshold = int(lines[1].split(":")[1])

    return threshold

def load_all_shares(folder_path, n):
    shares = []
    for pid in range(1, n + 1):
        filename = os.path.join(folder_path, f"share_{pid}.txt")
        with open(filename, "r") as f:
            lines = f.readlines()
            s_i = int(lines[1].split(":")[1])
            r_i = int(lines[2].split(":")[1])
            shares.append((pid, s_i, r_i))
    return shares

def save_config(config_file, n, threshold, secret):
    """Save n, threshold, and secret to vault_config.txt."""
    with open(config_file, "w") as f:
        f.write(f"participants: {n}\n")
        f.write(f"threshold: {threshold}\n")
        f.write(f"secret: {secret}\n")

def adjust_threshold(folder, commitments_file, config_file):
    # Load current config — secret is needed to re-run VSS
    n, current_threshold, secret = load_config(config_file)

    print(f"\nCurrent threshold: {current_threshold}, Participants: {n}")
    new_threshold = int(input("Enter new threshold: "))

    # Use .create() — re-runs fresh VSS on the stored secret
    # No need to load old shares; they are fully replaced
    vault = DynamicThresholdVault.create(
        secret=secret,
        n=n,
        threshold=new_threshold
    )

    # Save updated shares to files
    save_shares_to_files(vault.shares, folder)

    # Save updated commitments
    with open(commitments_file, "w") as f:
        for i, c in enumerate(vault.commitments):
            f.write(f"C{i}: {c}\n")

    # Save updated config (preserve secret for future adjustments)
    save_config(config_file, n, new_threshold, secret)

    print(f"\n✅ Threshold updated from {current_threshold} → {new_threshold} successfully.")




# -----------------------------
# MAIN DEMO
# -----------------------------
def demo():

    print("\n1. Generate Shares")
    print("2. Reconstruct Secret")
    print("3. Adjust Threshold")
    choice = input("Enter choice: ")

    if choice == "1":

        file_path = input("Enter file path to derive secret from: ")
        n = int(input("Enter participants: "))
        t = int(input("Enter threshold: "))
        folder = input("Enter folder to save shares: ")

        secret = secret_from_file(file_path)

        print(f"\nDerived secret from file: {secret}")

        vss = PedersenVSS(secret, t, n)

        shares = vss.generate_all_shares()
        commitments = vss.get_public_commitments()

        # PARTICIPANTS VERIFY DEALER
        participant_verify_dealer(shares, commitments)

        # SAVE DATA
        save_shares_to_files(shares, folder)

        with open("commitments.txt", "w") as f:
            for i, c in enumerate(commitments):
                f.write(f"C{i}: {c}\n")

        save_config("vault_config.txt", n, t, secret)

        print("\nShares, commitments, and vault configuration saved.")

    elif choice == "2":

        folder = input("Enter share folder path: ")
        commitments_file = input("Enter commitments file path: ")
        config_file = input("Enter vault config file path: ")

        threshold = load_threshold(config_file)

        reconstruct_from_files(folder, commitments_file, threshold)

    elif choice == "3":
        folder = input("Enter share folder path: ")
        commitments_file = input("Enter commitments file path: ")
        config_file = input("Enter vault config file path: ")

        adjust_threshold(folder, commitments_file, config_file)

    else:
        print("Invalid choice.")


if __name__ == "__main__":
    demo()