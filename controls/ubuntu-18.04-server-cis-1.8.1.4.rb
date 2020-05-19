# encoding: UTF-8

control "C-1.8.1.4" do
  title "Ensure permissions on /etc/motd are configured"
  desc  "The contents of the `/etc/motd` file are displayed to users after
login and function as a message of the day for authenticated users."
  desc  "rationale", "If the `/etc/motd` file does not have the correct
ownership it could be modified by unauthorized users with incorrect or
misleading information."
  desc  "check", "
    Run the following command and verify `Uid` and `Gid` are both `0/root` and
`Access` is `644` :

    ```
    # stat /etc/motd

    Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)
    ```
  "
  desc  "fix", "
    Run the following commands to set permissions on `/etc/motd` :

    ```
    # chown root:root /etc/motd
    ```

    ```
    # chmod u-x,go-wx /etc/motd
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
  tag cis_rid: "1.8.1.4"

  describe file('/etc/motd') do
    it { should exist }
    it { should be_owned_by 'root' }
    it { should_not be_more_permissive_than('0644') }
  end

end

