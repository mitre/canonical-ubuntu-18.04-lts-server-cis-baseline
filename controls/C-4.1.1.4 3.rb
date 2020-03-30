# encoding: UTF-8

control "C-4.1.1.4" do
  title "Ensure audit_backlog_limit is sufficient"
  desc  "The backlog limit has a default setting of 64"
  desc  "rationale", "during boot if audit=1, then the backlog will hold 64
records. If more that 64 records are created during boot, auditd records will
be lost and potential malicious activity could go undetected."
  desc  "check", "
    Run the following commands and verify the `audit_backlog_limit=` parameter
is set to an appropriate size for your organization

    ```
    # grep \"^\\s*linux\" /boot/grub/grub.cfg | grep -v \"audit_backlog_limit=\"
    ```

    Nothing should be returned

    ```
    # grep \"audit_backlog_limit=\" /boot/grub/grub.cfg
    ```

    Ensure the the returned value complies with local site policy

    **Recommended that this value be `8192` or larger.**
  "
  desc "fix", "
    Edit /etc/default/grub and add `audit_backlog_limit=` to GRUB_CMDLINE_LINUX:

    **Example:**

    ```
    GRUB_CMDLINE_LINUX=\"audit_backlog_limit=8192\"
    ```

    Run the following command to update the grub2 configuration:

    ```
    # update-grub
    ```
  "
  impact 0.7
  tag severity: "high"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ["AU-12", "AU-3", "Rev_4"]
  tag cis_level: 2
  tag cis_controls: ["6.2", "6.3", "Rev_7"]
  tag cis_rid: "4.1.1.4"
end
