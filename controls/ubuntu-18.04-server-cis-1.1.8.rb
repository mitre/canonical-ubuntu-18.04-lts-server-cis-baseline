# encoding: UTF-8

control "C-1.1.8" do
  title "Ensure nodev option set on /var/tmp partition"
  desc  "The `nodev` mount option specifies that the filesystem cannot contain
special devices."
  desc  "rationale", "Since the `/var/tmp` filesystem is not intended to
support devices, set this option to ensure that users cannot attempt to create
block or character special devices in `/var/tmp` ."
  desc  "check", "
    Verify that the `nodev` option is set if a `/var/tmp` partition exists.

    Run the following command and verify that nothing is returned:

    ```
    # mount | grep -E '\\s/var/tmp\\s' | grep -v nodev
    ```
  "
  desc "fix", "
    Edit the `/etc/fstab` file and add `nodev` to the fourth field (mounting
options) for the `/var/tmp` partition. See the `fstab(5)` manual page for more
information.

    Run the following command to remount `/var/tmp` :

    ```
    # mount -o remount,nodev /var/tmp
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
  tag cis_rid: "1.1.8"

  describe mount('/var/tmp') do
    its('options') { should include 'nodev' }
  end

end
