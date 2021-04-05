# encoding: UTF-8

control "C-3.7" do
  title "Disable IPv6"
  desc  "Although IPv6 has many advantages over IPv4, not all organizations
have IPv6 or dual stack configurations implemented."
  desc  "rationale", "If IPv6 or dual stack is not to be used, it is
recommended that IPv6 be disabled to reduce the attack surface of the system."
  desc  "check", "
    Depending or your distribution, run the appropriate following command and
verify no lines should be returned.

    ```
    # grep \"^\\s*linux\" /boot/grub/grub.cfg | grep -v \"ipv6.disable=1\"
    ```
  "
  desc "fix", "
    Edit `/etc/default/grub` and add `ipv6.disable=1` to the
`GRUB_CMDLINE_LINUX` parameters:

    ```
    GRUB_CMDLINE_LINUX=\"ipv6.disable=1\"
    ```

    Run the following command to update the `grub2` configuration:

    ```
    # update-grub
    ```
  "
  impact 0.7
  tag severity: "high"
  tag nist: ["RA-5", "CM-6", "CM-8", "SC-7(5)"]
  tag cis_level: 2
  tag cis_controls: ["3", "11", "9.1", "9.4"]
  tag cis_cdc_version: "7"
  tag cis_rid: "3.7"

  describe command('grep "^\\s*linux" /boot/grub/grub.cfg | grep -v "ipv6.disable=1"') do
    its('stdout') { should be_empty }
  end
end
