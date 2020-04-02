# encoding: UTF-8

control "C-1.5.1" do
  title "Ensure permissions on bootloader config are configured"
  desc  "The grub configuration file contains information on boot settings and
passwords for unlocking boot options.
     The grub configuration is usually `grub.cfg` stored in `/boot/grub/`.
  "
  desc  "rationale", "Setting the permissions to read and write for root only
prevents non-root users from seeing the boot parameters or changing them.
Non-root users who read the boot parameters may be able to identify weaknesses
in security upon boot and be able to exploit them."
  desc  "check", "
    Run the following command and verify `Uid` and `Gid` are both `0/root` and
`Access` does not grant permissions to `group` or `other` :

    ```
    # stat /boot/grub/grub.cfg

    Access: (0400/-r--------) Uid: ( 0/ root) Gid: ( 0/ root)
    ```
  "
  desc  "fix", "
    Run the following commands to set permissions on your grub configuration:

    ```
    # chown root:root /boot/grub/grub.cfg
    ```

    ```
    # chmod og-rwx /boot/grub/grub.cfg
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
  tag nist: ["CM-6", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["5.1", "Rev_7"]
  tag cis_rid: "1.5.1"

  describe file('/boot/grub/grub.cfg') do
    its ('uid') { should cmp 0 }
    its ('gid') { should cmp 0 }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
    it { should_not be_grouped_into 'users' }
    its ('mode') { should cmp '0400' }
  end

end
