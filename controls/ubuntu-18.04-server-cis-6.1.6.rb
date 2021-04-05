# encoding: UTF-8

control "C-6.1.6" do
  title "Ensure permissions on /etc/passwd- are configured"
  desc  "The `/etc/passwd-` file contains backup user account information."
  desc  "rationale", "It is critical to ensure that the `/etc/passwd-` file is
protected from unauthorized access. Although it is protected by default, the
file permissions could be changed either inadvertently or through malicious
actions."
  desc  "check", "
    Run the following command and verify `Uid` and `Gid` are both `0/root` and
`Access` is `600` or more restrictive:

    ```
    # stat /etc/passwd-

    Access: (0600/-rw-------) Uid: ( 0/ root) Gid: ( 0/ root)
    ```
  "
  desc  "fix", "
    Run the following command to set permissions on `/etc/passwd-` :

    ```
    # chown root:root /etc/passwd-

    # chmod u-x,go-rwx /etc/passwd-
    ```
  "
  impact 0.5
  tag severity: "medium"
  tag nist: ["SC-28"]
  tag cis_level: 1
  tag cis_controls: ["16.4"]
  tag cis_cdc_version: "7"
  tag cis_rid: "6.1.6"

  describe file('/etc/passwd-') do
    it { should_not be_more_permissive_than('0600') }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end
