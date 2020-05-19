# encoding: UTF-8

control "C-2.2.1.2" do
  title "Ensure systemd-timesyncd is configured"
  desc  "systemd-timesyncd is a daemon that has been added for synchronizing
the system clock across the network. It implements an SNTP client. In contrast
to NTP implementations such as chrony or the NTP reference server this only
implements a client side, and does not bother with the full NTP complexity,
focusing only on querying time from one remote server and synchronizing the
local clock to it. The daemon runs with minimal privileges, and has been hooked
up with networkd to only operate when network connectivity is available. The
daemon saves the current clock to disk every time a new NTP sync has been
acquired, and uses this to possibly correct the system clock early at bootup,
in order to accommodate for systems that lack an RTC such as the Raspberry Pi
and embedded devices, and make sure that time monotonically progresses on these
systems, even if it is not always correct. To make use of this daemon a new
system user and group \"systemd-timesync\" needs to be created on installation
of systemd.

    **Note:** The systemd-timesyncd service specifically implements only SNTP.
This minimalistic service will set the system clock for large offsets or slowly
adjust it for smaller deltas. More complex use cases are not covered by
systemd-timesyncd.

    This recommendation only applies if timesyncd is in use on the system.
  "
  desc  "rationale", "Proper configuration is vital to ensuring time
synchronization is working properly."
  desc  "check", "
    Ensure that timesyncd is enabled and started

    Run the following commands:

    ```
    # systemctl is-enabled systemd-timesyncd.service
    ```

    This should return:

    ```
    enabled
    ```

    Review `/etc/systemd/timesyncd.conf` and ensure that the NTP servers, NTP
FallbackNTP servers, and RootDistanceMaxSec listed are in accordance with local
policy

    Run the following command

    ```
    # timedatectl status
    ```

    This should return something similar to:

    ```
     Local time: Tue 2019-06-04 15:40:45 EDT
     Universal time: Tue 2019-06-04 19:40:45 UTC
     RTC time: Tue 2019-06-04 19:40:45
     Time zone: America/New_York (EDT, -0400)
     NTP enabled: yes
    NTP synchronized: yes
     RTC in local TZ: no
     DST active: yes
     Last DST change: DST began at
     Sun 2019-03-10 01:59:59 EST
     Sun 2019-03-10 03:00:00 EDT
     Next DST change: DST ends (the clock jumps one hour backwards) at
     Sun 2019-11-03 01:59:59 EDT
     Sun 2019-11-03 01:00:00 EST
    ```
  "
  desc  "fix", "
    Run the following command to enable systemd-timesyncd

    ```
    # systemctl enable systemd-timesyncd.service
    ```

    edit the file /etc/systemd/timesyncd.conf and add/modify the following
lines in accordance with local site policy

    ```
    NTP=0.ubuntu.pool.ntp.org 1.ubuntu.pool.ntp.org 2.ubuntu.pool.ntp.org

    FallbackNTP=ntp.ubuntu.com 3.ubuntu.pool.ntp.org

    RootDistanceMaxSec=1
    ```

    Run the following commands to start systemd-timesyncd.service

    ```
    # systemctl start systemd-timesyncd.service
    ```

    ```
    # timedatectl set-ntp true
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
  tag cis_rid: "2.2.1.2"

  "
  describe service('systemd-timesyncd') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end


  describe file('/etc/systemd/timesyncd.conf') do
    it { should exist }
      #its('content') { should match(%r{FallbackNTP}) }
  end
"

  describe parse_config_file('/etc/systemd/timesyncd.conf') do
    its('NTP') { should match(%r{\w+\.\w+}) }
    its('FallbackNTP') { should match(%r{\w+\.\w+}) }
    its('RootDistanceMaxSec') { should cmp 1 }
  end
  describe parse_config_file('/etc/systemd/timesyncd.conf') do
    its('FallbackNTP') { should match(%r{\w+\.\w+}) }
  end
  describe parse_config_file('/etc/systemd/timesyncd.conf') do
    its('RootDistanceMaxSec') { should cmp '1' }
  end


end
