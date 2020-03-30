# encoding: UTF-8

control "C-1.1.19" do
  title "Ensure nosuid option set on removable media partitions"
  desc  "The `nosuid` mount option specifies that the filesystem cannot contain
`setuid` files."
  desc  "rationale", "Setting this option on a file system prevents users from
introducing privileged programs onto the system and allowing non-root users to
execute them."
  desc  "check", "
    Run the following command and verify that the `nosuid` option is set on all
removable media partitions.

    ```
    # mount
    ```
  "
  desc "fix", "Edit the `/etc/fstab` file and add `nosuid` to the fourth field
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
  tag nist: ["CM-6", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["5.1", "Rev_7"]
  tag cis_rid: "1.1.19"
end
