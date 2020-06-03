# encoding: UTF-8

control "C-3.5.2.1" do
  title "Ensure ufw service is enabled"
  desc  "UncomplicatedFirewall (ufw) is a frontend for iptables. ufw provides a
framework for managing netfilter, as well as a command-line and available
graphical user interface for manipulating the firewall.

    Ensure that the ufw service is enabled to protect your system.
  "
  desc  "rationale", "The ufw service must be enabled and running in order for
ufw to protect the system"
  desc  "check", "
    Run the following command to verify that ufw is enabled:

    ```
    # systemctl is-enabled ufw

    enabled
    ```

    Run the following command to verify that ufw is running:

    ```
    # ufw status | grep Status

    Status: active
    ```
  "
  desc  "fix", "
    Run the following command to enable ufw:

    ```
    # ufw enable
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
  tag cis_rid: "3.5.2.1"


  ufw_status = command('ufw status').stdout.strip.lines.first
  value = ufw_status.split(':')[1].strip

  describe 'UFW status' do
    subject { value }
    it { should cmp 'active' }
  end

  describe service('ufw') do
    it { should be_running }
    it { should be_enabled }
  end

end
