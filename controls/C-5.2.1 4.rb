# encoding: UTF-8

control "C-5.2.1" do
  title "Ensure permissions on /etc/ssh/sshd_config are configured"
  desc  "The `/etc/ssh/sshd_config` file contains configuration specifications
for `sshd`. The command below sets the owner and group of the file to root."
  desc  "rationale", "The `/etc/ssh/sshd_config` file needs to be protected
from unauthorized changes by non-privileged users."
  desc  "check", "
    Run the following command and verify `Uid` and `Gid` are both `0/root` and
`Access` does not grant permissions to `group` or `other`:

    ```
    # stat /etc/ssh/sshd_config

    Access: (0600/-rw-------) Uid: ( 0/ root) Gid: ( 0/ root)
    ```
  "
  desc  "fix", "
    Run the following commands to set ownership and permissions on
`/etc/ssh/sshd_config`:

    ```
    # chown root:root /etc/ssh/sshd_config
    ```

    ```
    # chmod og-rwx /etc/ssh/sshd_config
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
  tag nist: ["AC-3 (3)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["14.6", "Rev_7"]
  tag cis_rid: "5.2.1"
end
