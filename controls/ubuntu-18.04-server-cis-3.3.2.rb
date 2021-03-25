control "C-3.3.2" do
  title "Ensure /etc/hosts.allow is configured"
  desc  "The `/etc/hosts.allow` file specifies which IP addresses are permitted
to connect to the host. It is intended to be used in conjunction with the
`/etc/hosts.deny` file."
  desc  "rationale", "The `/etc/hosts.allow` file supports access control by IP
and helps ensure that only authorized systems can connect to the system."
  desc  "check", "
    Run the following command and verify the contents of the `/etc/hosts.allow`
file:

    ```
    # cat /etc/hosts.allow
    ```
  "
  desc  "fix", "
    Run the following command to create `/etc/hosts.allow`:

    ```
    # echo \"ALL: /, /, ...\" >/etc/hosts.allow
    ```
    where each `/` combination (for example, \"192.168.1.0/255.255.255.0\")
represents one network block in use by your organization that requires access
to this system.
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ["SC-7(5)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["9.4", "Rev_7"]
  tag cis_rid: "3.3.2"

  if file('/etc/hosts.allow').exist?
    my_hosts_allow = command('cat /etc/hosts.allow').stdout.strip
    describe "Contents of /etc/hosts.allow shall be evaluated manually " do
      skip " Contents of /etc/hosts.allow shall be evaluated manually.\n #{my_hosts_allow} "
    end
  else
    describe file('/etc/hosts.allow') do
      it { should exist }
    end
  end

end
