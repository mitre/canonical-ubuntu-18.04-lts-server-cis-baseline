# encoding: UTF-8

control "C-3.3.4" do
  title "Ensure permissions on /etc/hosts.allow are configured"
  desc  "The `/etc/hosts.allow` file contains networking information that is
used by many applications and therefore must be readable for these applications
to operate."
  desc  "rationale", "It is critical to ensure that the `/etc/hosts.allow` file
is protected from unauthorized write access. Although it is protected by
default, the file permissions could be changed either inadvertently or through
malicious actions."
  desc  "check", "
    Run the following command and verify `Uid` and `Gid` are both `0/root` and
`Access` is `644`:

    ```
    # stat /etc/hosts.allow
    Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)
    ```
  "
  desc  "fix", "
    Run the following commands to set permissions on `/etc/hosts.allow`:

    ```
    # chown root:root /etc/hosts.allow
    # chmod 644 /etc/hosts.allow
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
  tag cis_rid: "3.3.4"

  describe file('/etc/hosts.allow') do
    it { should be_owned_by 'root' }
    it { should_not be_more_permissive_than('0644') }
    it { should be_more_permissive_than('0000') }
  end
end
