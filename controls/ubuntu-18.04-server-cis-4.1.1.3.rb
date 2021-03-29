# encoding: UTF-8

control "C-4.1.1.3" do
  title "Ensure auditing for processes that start prior to auditd is enabled"
  desc  "Configure `grub` so that processes that are capable of being audited
can be audited even if they start up prior to `auditd` startup."
  desc  "rationale", "Audit events need to be captured on processes that start
up prior to `auditd` , so that potential malicious activity cannot go
undetected."
  desc  "check", "
    Run the following command and verify that each linux line has the `audit=1`
parameter set:

    ```
    # grep \"^\\s*linux\" /boot/grub/grub.cfg | grep -v \"audit=1\" | grep -v
'/boot/memtest86+.bin'
    ```

    Nothing should be returned
  "
  desc "fix", "
    Edit `/etc/default/grub` and add audit=1 to GRUB_CMDLINE_LINUX:

    ```
    GRUB_CMDLINE_LINUX=\"audit=1\"
    ```

    Run the following command to update the `grub2` configuration:

    ```
    # update-grub
    ```
  "
  impact 0.7
  tag severity: "high"
  tag nist: ["AU-12", "AU-3"]
  tag cis_level: 2
  tag cis_controls: ["6.2", "6.3"]
  tag cis_cdc_version: "7"
  tag cis_rid: "4.1.1.3"
  describe command("grep \"^\\s*linux\" /boot/grub/grub.cfg | grep -v \"audit=1\" | grep -v '/boot/memtest86+.bin'").stdout do
    it { should be_empty }
  end
end
