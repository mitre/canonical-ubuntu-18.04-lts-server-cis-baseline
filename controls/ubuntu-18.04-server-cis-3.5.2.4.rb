# encoding: UTF-8

control "C-3.5.2.4" do
  title "Ensure outbound connections are configured"
  desc  "Configure the firewall rules for new outbound connections."
  desc  "rationale", "If rules are not in place for new outbound connections
all packets will be dropped by the default policy preventing network usage."
  desc  "check", "
    Run the following command and verify all rules for new outbound connections
match site policy:

    ```
    # ufw status numbered
    ```
  "
  desc "fix", "
    Configure ufw in accordance with site policy. The following commands will
implement a policy to allow all outbound connections on all interfaces:

    ```
    # ufw allow out on all
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
  tag cis_rid: "3.5.2.4"

  ufw_status = command('ufw status numbered').stdout.strip

  if service('ufw').running? && service('ufw').enabled?
    describe "File '#{ufw_status}' \n Manually verification required.\nVerify all rules for new outbound connections
match site policy" do
      skip "File '#{ufw_status}' \n Manually verification required.\nVerify all rules for new outbound connections
match site policy"
    end
  else
    describe service('ufw') do
      it { should be_running }
      it { should be_enabled }
    end
  end
end

