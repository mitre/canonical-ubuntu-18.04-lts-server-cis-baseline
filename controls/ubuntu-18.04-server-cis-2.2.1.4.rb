# encoding: UTF-8

control "C-2.2.1.4" do
  title "Ensure ntp is configured"
  desc  "`ntp` is a daemon which implements the Network Time Protocol (NTP). It
is designed to synchronize system clocks across a variety of systems and use a
source that is highly accurate. More information on NTP can be found at
[http://www.ntp.org](http://www.ntp.org/). `ntp` can be configured to be a
client and/or a server.

    This recommendation only applies if ntp is in use on the system.
  "
  desc  "rationale", "If ntp is in use on the system proper configuration is
vital to ensuring time synchronization is working properly."
  desc  "check", "
    Run the following command and verify output matches:

    ```
    # grep \"^restrict\" /etc/ntp.conf
    restrict -4 default kod nomodify notrap nopeer noquery
    restrict -6 default kod nomodify notrap nopeer noquery
    ```

    The `-4` in the first line is optional and options after `default` can
appear in any order. Additional restriction lines may exist.

    Run the following command and verify remote server is configured properly:

    ```
    # grep -E \"^(server|pool)\" /etc/ntp.conf
    server
    ```

    Multiple servers may be configured.

    Verify that `ntp` is configured to run as the `ntp` user by running one of
the following commands as appropriate for your distribution and verifying
output matches:

    ```
    # grep \"^OPTIONS\" /etc/sysconfig/ntpd
    OPTIONS=\"-u ntp:ntp\"
    # grep \"^NTPD_OPTIONS\" /etc/sysconfig/ntp
    OPTIONS=\"-u ntp:ntp\"
    ```

    Additional options may be present.

    ```
    # grep \"RUNASUSER=ntp\" /etc/init.d/ntp
    RUNASUSER=ntp
    ```
  "
  desc  "fix", "
    Add or edit restrict lines in `/etc/ntp.conf` to match the following:

    ```
    restrict -4 default kod nomodify notrap nopeer noquery
    restrict -6 default kod nomodify notrap nopeer noquery
    ```

    Add or edit server or pool lines to `/etc/ntp.conf` as appropriate:

    ```
    server
    ```

    Configure `ntp` to run as the `ntp` user by adding or editing one of the
following files as appropriate for your distribution:
    `/etc/sysconfig/ntpd` :

    ```
    OPTIONS=\"-u ntp:ntp\"
    ```

    `/etc/sysconfig/ntp` :

    ```
    NTPD_OPTIONS=\"-u ntp:ntp\"
    ```

    `/etc/init.d/ntp`:

    ```
    RUNASUSER=ntp
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
  tag nist: ["AU-8 (2)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["6.1", "Rev_7"]
  tag cis_rid: "2.2.1.4"

  #its('server') { should_not eq nil } || its('pool') { should_not eq nil }

  if package('ntp').installed?
    describe service('ntp') do
      it { should be_enabled }
      it { should be_running }
    end

    describe processes('ntpd') do
      it { should exist }
      its('users') { should include 'ntp'}
    end

    ntp_conf.restrict.each do |res|
      describe res do
        next unless res.include?('-4')
        it { should include 'default'}
        it { should include 'kod'}
        it { should include 'nomodify'}
        it { should include 'notrap'}
        it { should include 'nopeer'}
        it { should include 'noquery'}
      end
    end

    ntp_conf.restrict.each do |res|
      describe res do
        next unless res.include?('-6')
        it { should include 'default'}
        it { should include 'kod'}
        it { should include 'nomodify'}
        it { should include 'notrap'}
        it { should include 'nopeer'}
        it { should include 'noquery'}
      end
    end

    describe.one do
      describe ntp_conf('/etc/ntp.conf') do
        its('server') { should_not eq nil }
      end
      describe ntp_conf('/etc/ntp.conf') do
        its('pool') { should_not eq nil }
      end
    end

  else
    impact 0.0
    describe "The NTP package is not installed" do
      skip "The NTP package is not installed, this control is Not Applicable."
    end
  end
end

