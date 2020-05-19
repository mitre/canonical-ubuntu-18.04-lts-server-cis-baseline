# encoding: UTF-8

control "C-2.2.1.1" do
  title "Ensure time synchronization is in use"
  desc  "System time should be synchronized between all systems in an
environment. This is typically done by establishing an authoritative time
server or set of servers and having all systems synchronize their clocks to
them."
  desc  "rationale", "Time synchronization is important to support time
sensitive security mechanisms like Kerberos and also ensures log files have
consistent time records across the enterprise, which aids in forensic
investigations."
  desc  "check", "
    On physical systems or virtual systems where host based time
synchronization is not available verify that timesyncd, chrony, or NTP is
installed. Use one of the following commands to determine the needed
information:

    If systemd-timesyncd is used:

    ```
    # systemctl is-enabled systemd-timesyncd
    ```

    If chrony is used:

    ```
    # dpkg -s chrony
    ```

    If ntp is used:

    ```
    # dpkg -s ntp
    ```

    On virtual systems where host based time synchronization is available
consult your virtualization software documentation and verify that host based
synchronization is in use.
  "
  desc "fix", "
    On systems where host based time synchronization is not available,
configure systemd-timesyncd. If \"full featured\" and/or encrypted time
synchronization is required, install chrony or NTP.

    To install chrony:

    ```
    # atp install chrony
    ```

    To install ntp:

    ```
    # apt install ntp
    ```

    On virtual systems where host based time synchronization is available
consult your virtualization software documentation and setup host based
synchronization.
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ["AU-8 (2)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["6.1", "Rev_7"]
  tag cis_rid: "2.2.1.1"

  describe.one do
    describe service('systemd-timesyncd') do
      it { should be_installed }
      it { should be_enabled }
      it { should be_running }
    end
    describe service('chrony') do
      it { should be_installed }
      it { should be_enabled }
      it { should be_running }
    end
    describe service('ntp') do
      it { should be_installed }
      it { should be_enabled }
      it { should be_running }
    end
  end

end

