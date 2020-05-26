# encoding: UTF-8

control "C-2.2.14" do
  title "Ensure SNMP Server is not enabled"
  desc  "The Simple Network Management Protocol (SNMP) server is used to listen
for SNMP commands from an SNMP management system, execute the commands or
collect the information and then send results back to the requesting system."
  desc  "rationale", "The SNMP server can communicate using SNMP v1, which
transmits data in the clear and does not require authentication to execute
commands. Unless absolutely necessary, it is recommended that the SNMP service
not be used. If SNMP is required the server should be configured to disallow
SNMP v1."
  desc  "check", "
    Run the following command to verify `snmpd` is not enabled:

    ```
    # systemctl is-enabled snmpd

    disabled
    ```

    Verify result is not \"enabled\".
  "
  desc  "fix", "
    Run the following command to disable `snmpd`:

    ```
    # systemctl --now disable snmpd
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
  tag nist: ["CM-7 (1)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["9.2", "Rev_7"]
  tag cis_rid: "2.2.14"

  if package('snmpd').installed?
    describe service('snmpd') do
      it { should_not be_enabled }
      it { should_not be_running }
    end
  else
    impact 0.0
    describe "The SNMP Server package is not installed" do
      skip "The SNMP Server package is not installed."
    end
  end
end
