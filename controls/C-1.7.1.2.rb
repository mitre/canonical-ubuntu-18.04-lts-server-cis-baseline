# encoding: UTF-8

control "C-1.7.1.2" do
  title "Ensure AppArmor is enabled in the bootloader configuration"
  desc  "Configure AppArmor to be enabled at boot time and verify that it has
not been overwritten by the bootloader boot parameters."
  desc  "rationale", "AppArmor must be enabled at boot time in your bootloader
configuration to ensure that the controls it provides are not overridden."
  desc  "check", "
    Run the following commands to verify that all linux lines have the
`apparmor=1` and `security=apparmor` parameters set:

    ```
    # grep \"^\\s*linux\" /boot/grub/grub.cfg | grep -v \"apparmor=1\" | grep -v '/boot/memtest86+.bin'

    Nothing should be returned
    ```

    ```
    # grep \"^\\s*linux\" /boot/grub/grub.cfg | grep -v \"security=apparmor\" | grep -v '/boot/memtest86+.bin'

    Nothing should be returned
    ```
  "
  desc "fix", "
    edit `/etc/default/grub` and add the appermor=1 and security=apparmor
parameters to the GRUB_CMDLINE_LINUX= line

    ```
    GRUB_CMDLINE_LINUX=\"apparmor=1 security=apparmor\"
    ```

    Run the following command to update the `grub2` configuration:

    ```
    # update-grub
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
  tag nist: ["AC-3 (3)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["14.6", "Rev_7"]
  tag cis_rid: "1.7.1.2"

  describe service('apparmor') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end

    describe grub_conf('/boot/grub/grub.cfg') do
      its('kernel') { should include 'apparmor=1' }
      its('kernel') { should include 'security=apparmor' }
    end

end
