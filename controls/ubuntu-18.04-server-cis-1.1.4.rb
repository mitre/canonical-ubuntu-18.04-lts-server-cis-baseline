# encoding: UTF-8

control "C-1.1.4" do
  title "Ensure nosuid option set on /tmp partition"
  desc  "The `nosuid` mount option specifies that the filesystem cannot contain
`setuid` files."
  desc  "rationale", "Since the `/tmp` filesystem is only intended for
temporary file storage, set this option to ensure that users cannot create
`setuid` files in `/tmp` ."
  desc  "check", "
    Verify that the `nosuid` option is set if a `/tmp` partition exists

    Run the following command and verify that nothing is returned:

    ```
    # mount | grep -E '\\s/tmp\\s' | grep -v nosuid
    ```
  "
  desc "fix", "
    Edit the `/etc/fstab` file and add `nosuid` to the fourth field (mounting
options) for the `/tmp` partition. See the `fstab(5)` manual page for more
information.

    Run the following command to remount `/tmp` :
    ```
    # mount -o remount,nosuid /tmp
    ```

    or

    Edit `/etc/systemd/system/local-fs.target.wants/tmp.mount` to add `nosuid`
to the `/tmp` mount options:
    ```
    [Mount]
    Options=mode=1777,strictatime,noexec,nodev,nosuid
    ```
    Run the following command to remount `/tmp` :
    ```
    # mount -o remount,nosuid /tmp
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
  tag cis_rid: "1.1.4"

  describe mount('/tmp') do
    its('options') { should  include 'nosuid' }
  end

end
