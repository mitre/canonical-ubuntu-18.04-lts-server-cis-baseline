# encoding: UTF-8

control "C-1.1.17" do
  title "Ensure noexec option set on /dev/shm partition"
  desc  "The `noexec` mount option specifies that the filesystem cannot contain
executable binaries."
  desc  "rationale", "Setting this option on a file system prevents users from
executing programs from shared memory. This deters users from introducing
potentially malicious software on the system."
  desc  "check", "
    Verify that the `noexec` option is set if a `/dev/shm` partition exists.

    Run the following command and verify that nothing is returned:

    ```
    # mount | grep -E '\\s/dev/shm\\s' | grep -v noexec
    ```
  "
  desc "fix", "
    Edit the `/etc/fstab` file and add `noexec` to the fourth field (mounting
options) for the `/dev/shm` partition. See the `fstab(5)` manual page for more
information.

    Run the following command to remount `/dev/shm`:

    ```
    # mount -o remount,noexec /dev/shm
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
  tag nist: ["CM-2 (2)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["2.6", "Rev_7"]
  tag cis_rid: "1.1.17"

  describe mount('/dev/shm') do
    its('options') { should include 'noexec' }
  end

end
