# encoding: UTF-8

control "C-1.1.9" do
  title "Ensure nosuid option set on /var/tmp partition"
  desc  "The `nosuid` mount option specifies that the filesystem cannot contain
`setuid` files."
  desc  "rationale", "Since the `/var/tmp` filesystem is only intended for
temporary file storage, set this option to ensure that users cannot create
`setuid` files in `/var/tmp` ."
  desc  "check", "
    Verify that the `nosuid` option is set if a `/var/tmp` partition exists.

    Run the following command and verify that nothing is returned:

    ```
    # mount | grep -E '\\s/var/tmp\\s' | grep -v nosuid
    ```
  "
  desc "fix", "
    Edit the `/etc/fstab` file and add `nosuid` to the fourth field (mounting
options) for the `/var/tmp` partition. See the `fstab(5)` manual page for more
information.

    Run the following command to remount `/var/tmp` :
    ```
    # mount -o remount,nosuid /var/tmp
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
  tag cis_rid: "1.1.9"

  describe mount('/var/tmp') do
    its('options') { should include 'nosuid' }
  end
end
