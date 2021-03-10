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
  tag nist: ["AC-3 (3)"]
  tag cis_level: 1
  tag cis_controls: ["14.6"]
  tag cis_rid: "5.2.1"
  tag cis_scored: true
  tag cis_version: "2.0.1"
  tag cis_cdc_version: 7
  describe file('/etc/ssh/sshd_config') do
    it { should be_file }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
    it { should_not be_more_permissive_than('0600') }
  end
end
