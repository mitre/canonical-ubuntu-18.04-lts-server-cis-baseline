# encoding: UTF-8

control "C-5.3.4" do
  title "Ensure password hashing algorithm is SHA-512"
  desc  "The commands below change password encryption from `md5` to `sha512`
(a much stronger hashing algorithm). All existing accounts will need to perform
a password change to upgrade the stored hashes to the new algorithm."
  desc  "rationale", "
    The SHA-512 algorithm provides much stronger hashing than MD5, thus
providing additional protection to the system by increasing the level of effort
for an attacker to successfully determine passwords.

    Note that these change only apply to accounts configured on the local
system.
  "
  desc  "check", "
    Run the following commands and ensure the sha512 option is included in all
results:

    ```
    # grep -E
'^\\s*password\\s+(\\S+\\s+)+pam_unix\\.so\\s+(\\S+\\s+)*sha512\\s*(\\S+\\s*)*(\\s+#.*)?$'
/etc/pam.d/common-password
    ```

    Output should be similar to:

    ```
    password [success=1 default=ignore] pam_unix.so obscure sha512
    ```
  "
  desc "fix", "
    Edit the `/etc/pam.d/common-password` file to include the `sha512` option
for `pam_unix.so` as shown:

    ```
    password [success=1 default=ignore] pam_unix.so sha512
    ```
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ["SC-28", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["16.4", "Rev_7"]
  tag cis_rid: "5.3.4"
end
