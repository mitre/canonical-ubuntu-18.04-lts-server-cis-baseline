# encoding: UTF-8

control "C-3.3.3" do
  title "Ensure /etc/hosts.deny is configured"
  desc  "The `/etc/hosts.deny` file specifies which IP addresses are **not**
permitted to connect to the host. It is intended to be used in conjunction with
the `/etc/hosts.allow` file."
  desc  "rationale", "The `/etc/hosts.deny` file serves as a failsafe so that
any host not specified in `/etc/hosts.allow` is denied access to the system."
  desc  "check", "
    Run the following command and verify the contents of the `/etc/hosts.deny`
file:

    ```
    # cat /etc/hosts.deny
    ALL: ALL
    ```
  "
  desc  "fix", "
    Run the following command to create `/etc/hosts.deny`:

    ```
    # echo \"ALL: ALL\" >> /etc/hosts.deny
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
  tag nist: ["SC-7(5)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["9.4", "Rev_7"]
  tag cis_rid: "3.3.3"

  if file('/etc/hosts.deny').exist?
    my_hosts_deny = command('cat /etc/hosts.allow').stdout.strip
    describe "Contents of /etc/hosts.deny shall be evaluated manually " do
      skip " Contents of /etc/hosts.deny shall be evaluated manually.\n #{my_hosts_deny} "
    end
  else
    describe file('/etc/hosts.deny') do
      it { should exist }
    end
  end

end
