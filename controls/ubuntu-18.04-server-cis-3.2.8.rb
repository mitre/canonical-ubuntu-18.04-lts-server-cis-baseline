# encoding: UTF-8

control "C-3.2.8" do
  title "Ensure TCP SYN Cookies is enabled"
  desc  "When `tcp_syncookies` is set, the kernel will handle TCP SYN packets
normally until the half-open connection queue is full, at which time, the SYN
cookie functionality kicks in. SYN cookies work by not using the SYN queue at
all. Instead, the kernel simply replies to the SYN with a SYN|ACK, but will
include a specially crafted TCP sequence number that encodes the source and
destination IP address and port number and the time the packet was sent. A
legitimate connection would send the ACK packet of the three way handshake with
the specially crafted sequence number. This allows the system to verify that it
has received a valid response to a SYN cookie and allow the connection, even
though there is no corresponding SYN in the queue."
  desc  "rationale", "Attackers use SYN flood attacks to perform a denial of
service attacked on a system by sending many SYN packets without completing the
three way handshake. This will quickly use up slots in the kernel's half-open
connection queue and prevent legitimate connections from succeeding. SYN
cookies allow the system to keep accepting valid connections, even if under a
denial of service attack."
  desc  "check", "
    Run the following commands and verify output matches:

    ```
    # sysctl net.ipv4.tcp_syncookies

    net.ipv4.tcp_syncookies = 1
    ```

    ```
    # grep \"net\\.ipv4\\.tcp_syncookies\" /etc/sysctl.conf /etc/sysctl.d/*

    net.ipv4.tcp_syncookies = 1
    ```
  "
  desc  "fix", "
    Set the following parameters in `/etc/sysctl.conf` or a `/etc/sysctl.d/*`
file:

    ```
    net.ipv4.tcp_syncookies = 1
    ```

    Run the following commands to set the active kernel parameters:

    ```
    # sysctl -w net.ipv4.tcp_syncookies=1
    ```

    ```
    # sysctl -w net.ipv4.route.flush=1
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
  tag nist: ["CM-6", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["5.1", "Rev_7"]
  tag cis_rid: "3.2.8"

  describe kernel_parameter('net.ipv4.tcp_syncookies') do
    its('value') { should cmp '1' }
  end

end
