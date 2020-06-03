# encoding: UTF-8

control "C-3.5.1.1" do
  title "Ensure a Firewall package is installed"
  desc  "A Firewall package should be selected. Most firewall configuration
utilities operate as a front end to nftables or iptables."
  desc  "rationale", "A Firewall package is required for firewall management
and configuration."
  desc  "check", "
    Run **one** of the following commands to verify that a Firewall package is
installed that follows local site policy:

    To verify that `Uncomplicated Firewall` (`UFW`) is installed, run the
following command:

    ```
    # dpkg -s ufw | grep -i status

    Status: install ok installed
    ```

    To verify that `nftables` is installed, run the following command:

    ```
    # dpkg -s nftables | grep -i status

    Status: install ok installed
    ```

    To verify that `iptables` is installed, run the following command:

    ```
    # dpkg -s iptables | grep -i status

    Status: install ok installed
    ```
  "
  desc  "fix", "
    Run **one** of the following commands to install the Firewall package that
follows local site policy:

    To install `UFW`, run the following command:

    ```
    # apt install ufw
    ```

    To install `nftables`, run the following command:

    ```
    # apt install nftables
    ```

    To install `iptables`, run the following command:

    ```
    # apt install iptables
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
  tag cis_rid: "3.5.1.1"

  describe.one do
    describe package('ufw') do
      it { should be_installed }
    end
    describe package('nftables') do
      it { should be_installed }
    end
    describe package('iptables') do
      it { should be_installed }
    end
  end
end
