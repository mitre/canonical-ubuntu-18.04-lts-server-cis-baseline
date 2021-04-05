# encoding: UTF-8

control "C-6.1.5" do
  title "Ensure permissions on /etc/group are configured"
  desc  "The `/etc/group` file contains a list of all the valid groups defined
in the system. The command below allows read/write access for root and read
access for everyone else."
  desc  "rationale", "The `/etc/group` file needs to be protected from
unauthorized changes by non-privileged users, but needs to be readable as this
information is used with many non-privileged programs."
  desc  "check", "
    Run the following command and verify `Uid` and `Gid` are both `0/root` and
`Access` is `644` :

    ```
    # stat /etc/group

    Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)
    ```
  "
  desc  "fix", "
    Run the following command to set permissions on `/etc/group` :

    ```
    # chown root:root /etc/group

    # chmod 644 /etc/group
    ```
  "
  impact 0.5
  tag severity: "medium"
  tag nist: ["SC-28"]
  tag cis_level: 1
  tag cis_controls: ["16.4"]
  tag cis_cdc_version: "7"
  tag cis_rid: "6.1.5"

  describe file('/etc/group') do
    it { should_not be_more_permissive_than('0644') }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end
