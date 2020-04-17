# encoding: UTF-8

control "C-1.1.14" do
  title "Ensure nodev option set on /home partition"
  desc  "The `nodev` mount option specifies that the filesystem cannot contain
special devices."
  desc  "rationale", "Since the user partitions are not intended to support
devices, set this option to ensure that users cannot attempt to create block or
character special devices."
  desc  "check", "
    Verify that the `nodev` option is set if a `/home` partition exists.

    Run the following command and verify that nothing is returned:

    ```
    # mount | grep -E '\\s/home\\s' | grep -v nodev
    ```
  "
  desc "fix", "
    Edit the `/etc/fstab` file and add `nodev` to the fourth field (mounting
options) for the `/home` partition. See the `fstab(5)` manual page for more
information.

    ```
    # mount -o remount,nodev /home
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
  tag cis_rid: "1.1.14"

  describe mount('/home') do
    its('options') { should include 'nodev' }
  end

end
