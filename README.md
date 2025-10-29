# 🛡️ CIS Oracle Linux 9 Hardening Script

This Bash script automates the application of security configurations based on the [CIS Benchmark for Oracle Linux 9](https://www.cisecurity.org/benchmark/oracle_linux). It helps system administrators enforce best practices for system hardening, reduce attack surface, and improve compliance posture in enterprise environments.

---

## 🚀 What It Does

- Applies Level 1 CIS controls for Oracle Linux 9
- Configures system-wide security settings:
  - File permissions and ownership
  - Audit policies and logging
  - Kernel and network parameters
  - User account and password policies
  - Service and daemon restrictions
  - GRUB bootloader protection
- Uses modular functions for each control group
- Logs actions and results for auditability
- Designed for interactive or automated execution

---

## 📦 Requirements

- Oracle Linux 9 (fresh or existing install)
- Root privileges (`sudo`)
- Core system utilities:
  - `awk`, `sed`, `grep`, `firewalld`, `auditctl`, `systemctl`, `dnf`, `passwd`, `chage`, `find`, `stat`, `sysctl`, `crontab`

Install missing tools:
```bash
sudo dnf install audit firewalld
```

---

## 🧪 How to Run

1. Clone the repository:
   ```bash
   git clone https://github.com/behnam0x/cis-oracle-linux-9-apply-script.git
   cd cis-oracle-linux-9-apply-script
   ```

2. Make the script executable:
   ```bash
   chmod +x cis-oracle-linux-9-apply-script
   ```

3. Run the script with root privileges:
   ```bash
   sudo ./cis-oracle-linux-9-apply-script
   ```

---

## 📊 Logging and Audit Trail

All actions performed by the script are logged to:

```
/var/log/cis-oracle-apply.log
```

This log includes:
- Timestamps for each control applied
- Command outputs and status messages
- Success or failure indicators for each step

Use this log to:
- Audit changes made to the system
- Troubleshoot failed steps
- Verify compliance with CIS controls

---

## 🔐 GRUB Password Protection

The script includes a section to secure the GRUB bootloader with a password. This prevents unauthorized users from editing boot parameters or entering recovery mode.

To customize the GRUB password:

1. Generate a secure hash:
   ```bash
   grub2-mkpasswd-pbkdf2
   ```

2. Copy the resulting hash and insert it into the script:
   ```bash
   GRUB_PASSWORD_HASH="grub.pbkdf2.sha512.10000.XXXXXXXXXXXXXXXXXXXXXXXXXXXX"
   ```

3. The script will automatically update `/etc/grub.d/01_users` and regenerate the GRUB config.

> ⚠️ Make sure to test GRUB changes carefully. A misconfigured bootloader can prevent system startup.

---

## ⚙️ Customization Options

You can customize the script by editing variables and toggling modules:

- **GRUB password**: Set your own hash as shown above
- **Excluded services**: Comment out functions for services you want to keep
- **Audit rules**: Modify or extend auditd configurations
- **Firewall settings**: Adjust firewalld rules to match your network policy
- **Password policies**: Tune `PASS_MAX_DAYS`, `PASS_MIN_DAYS`, `PASS_WARN_AGE` in `/etc/login.defs`

---

## ⚠️ Important Precautions

> **Before running this script:**

- 🧷 **Take a snapshot or full backup** of your system. CIS hardening modifies critical system settings and may impact services, user access, or compatibility with existing applications.
- 🧪 **Test on a non-production machine** first to evaluate the impact.
- 🔍 **Review the script manually** if you have custom configurations or sensitive workloads.

---

## 📄 License

This project is licensed under the [MIT License](https://github.com/behnam0x/cis-oracle-linux-9-apply-script/blob/main/LICENSE). Feel free to modify and share.

---

## 🙋‍♂️ Contributions

Pull requests and suggestions are welcome! If you have improvements, additional CIS rules, or want to adapt this for other Linux distributions, feel free to contribute.

---

## 🌐 Related Resources

- [CIS Benchmark for Oracle Linux](https://www.cisecurity.org/benchmark/oracle_linux)
- [Auditd Documentation](https://linux.die.net/man/8/auditd)
- [Firewalld Guide](https://firewalld.org/documentation/)
- [GRUB Security](https://www.gnu.org/software/grub/manual/grub/grub.html#Security)
