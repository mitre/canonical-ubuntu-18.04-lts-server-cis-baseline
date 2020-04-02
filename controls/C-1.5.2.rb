# encoding: UTF-8

control "C-1.5.2" do
  title "Ensure bootloader password is set"
  desc  "Setting the boot loader password will require that anyone rebooting
the system must enter a password before being able to set command line boot
parameters"
  desc  "rationale", "Requiring a boot password upon execution of the boot
loader will prevent an unauthorized user from entering boot parameters or
changing the boot partition. This prevents users from weakening security (e.g.
turning off AppArmor at boot time)."
  desc  "check", "
    Run the following commands and verify output matches:

    ```
    # grep \"^set superusers\" /boot/grub/grub.cfg

    set superusers=\"\"
    ```

    ```
    # grep \"^password\" /boot/grub/grub.cfg

    password_pbkdf2
    ```
  "
  desc "fix", "
    Create an encrypted password with `grub-mkpasswd-pbkdf2`:

    ```
    # grub-mkpasswd-pbkdf2
    Enter password:

    Reenter password:

    Your PBKDF2 is
    ```
    Add the following into a custom `/etc/grub.d` configuration file:

    ```
    cat
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
  tag cis_rid: "1.5.2"

  # grub_conf resource does not support this yet ...
  #describe grub_conf('/boot/grub/grub.cfg') do
  #  its('content') { should match '^password_pbkdf2' }
  #end

  describe file('/boot/grub/grub.cfg') do
    its('content') { should match '^\\s*superusers\\s*=' }
  end
  describe file('/boot/grub/grub.cfg') do
    its('content') { should match '^\\s*password_pbkdf2' }
  end

end
