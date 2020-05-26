# encoding: UTF-8

control "C-3.3.1" do
  title "Ensure TCP Wrappers is installed"
  desc  "Many Linux distributions provide value-added firewall solutions which
provide easy, advanced management of network traffic into and out of the local
system. When these solutions are available and appropriate for an environment
they should be used.

    In cases where a value-added firewall is not provided by a distribution,
TCP Wrappers provides a simple access list and standardized logging method for
services capable of supporting it. Services that are called from `inetd` and
`xinetd` support the use of TCP wrappers. Any service that can support TCP
wrappers will have the `libwrap.so` library attached to it.
  "
  desc  "rationale", "TCP Wrappers provide a good simple access list mechanism
to services that may not have that support built in. It is recommended that all
services that can support TCP Wrappers, use it."
  desc  "check", "
    Run the following command and verify TCP Wrappers is installed:

    ```
    # dpkg -s tcpd
    ```
  "
  desc  "fix", "
    Run the following command to install TCP Wrappers:

    ```
    # apt install tcpd
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
  tag cis_rid: "3.3.1"

  describe package('tcpd') do
    it { should be_installed }
  end

end

