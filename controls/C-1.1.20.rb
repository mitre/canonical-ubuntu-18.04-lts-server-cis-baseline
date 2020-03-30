# encoding: UTF-8

control "C-1.1.20" do
  title "Ensure noexec option set on removable media partitions"
  desc  "The `noexec` mount option specifies that the filesystem cannot contain
executable binaries."
  desc  "rationale", "Setting this option on a file system prevents users from
executing programs from the removable media. This deters users from being able
to introduce potentially malicious software on the system."
  desc  "check", "
    Run the following command and verify that the `noexec` option is set on all
removable media partitions.

    ```
    # mount
    ```
  "
  desc "fix", "Edit the `/etc/fstab` file and add `noexec` to the fourth field
(mounting options) of all removable media partitions. Look for entries that
have mount points that contain words such as floppy or cdrom. See the
`fstab(5)` manual page for more information."
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
  tag cis_rid: "1.1.20"
end
