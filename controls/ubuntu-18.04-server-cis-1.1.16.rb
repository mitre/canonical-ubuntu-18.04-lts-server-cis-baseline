# encoding: UTF-8

control "C-1.1.16" do
  title "Ensure nosuid option set on /dev/shm partition"
  desc  "The `nosuid` mount option specifies that the filesystem cannot contain
`setuid` files."
  desc  "rationale", "Setting this option on a file system prevents users from
introducing privileged programs onto the system and allowing non-root users to
execute them."
  desc  "check", "
    Verify that the `nosuid` option is set if a `/dev/shm` partition exists.

    Run the following command and verify that nothing is returned:

    ```
    # mount | grep -E '\\s/dev/shm\\s' | grep -v nosuid
    ```
  "
  desc "fix", "
    Edit the `/etc/fstab` file and add `nosuid` to the fourth field (mounting
options) for the `/dev/shm` partition. See the `fstab(5)` manual page for more
information.

    Run the following command to remount `/dev/shm` :

    ```
    # mount -o remount,nosuid /dev/shm
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
  tag cis_rid: "1.1.16"

  describe mount('/dev/shm') do
    its('options') { should include 'nosuid' }
  end

end
