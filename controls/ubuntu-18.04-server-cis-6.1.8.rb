# encoding: UTF-8

control "C-6.1.8" do
  title "Ensure permissions on /etc/group- are configured"
  desc  "The `/etc/group-` file contains a backup list of all the valid groups
defined in the system."
  desc  "rationale", "It is critical to ensure that the `/etc/group-` file is
protected from unauthorized access. Although it is protected by default, the
file permissions could be changed either inadvertently or through malicious
actions."
  desc  "check", "
    Run the following command and verify `Uid` and `Gid` are both `0/root` and
`Access` is `644` or more restrictive:

    ```
    # stat /etc/group-

    Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)
    ```
  "
  desc  "fix", "
    Run the following command to set permissions on `/etc/group-` :

    ```
    # chown root:root /etc/group-

    # chmod u-x,go-wx /etc/group-
    ```
  "
  impact 0.5
  tag severity: "medium"
  tag nist: ["SC-28"]
  tag cis_level: 1
  tag cis_controls: ["16.4"]
  tag cis_cdc_version: "7"
  tag cis_rid: "6.1.8"

  describe file('/etc/group') do
    it { should_not be_more_permissive_than('0644') }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end
