# encoding: UTF-8

control "C-3.5.2.5" do
  title "Ensure firewall rules exist for all open ports"
  desc  "Any ports that have been opened on non-loopback addresses need
firewall rules to govern traffic."
  desc  "rationale", "Without a firewall rule configured for open ports default
firewall policy will drop all packets to these ports."
  desc  "check", "
    Run the following command to determine open ports:

    ```
    # ss -4tuln
    ```

    ```
    Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port
    udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*
    udp UNCONN 0 0 10.105.106.117%enp1s0:68 0.0.0.0:*
    tcp LISTEN 0 128 127.0.0.53%lo:53 0.0.0.0:*
    tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
    ```

    Run the following command to determine firewall rules:

    ```
    # ufw status
    ```

    ```
    Status: active

     To Action From
     -- ------ ----
    [ 1] Anywhere on lo ALLOW IN Anywhere
    [ 2] Anywhere ALLOW OUT Anywhere on lo (out)
    [ 3] Anywhere DENY IN 127.0.0.0/8
    [ 4] 22/tcp ALLOW IN Anywhere
    [ 5] Anywhere ALLOW OUT Anywhere on enp1s0 (out)
    [ 6] Anywhere ALLOW OUT Anywhere on all (out)
    [ 7] Anywhere (v6) on lo ALLOW IN Anywhere (v6)
    [ 8] Anywhere (v6) ALLOW OUT Anywhere (v6) on lo (out)
    [ 9] Anywhere (v6) DENY IN ::1
    [10] 22/tcp (v6) ALLOW IN Anywhere (v6)
    [11] Anywhere (v6) ALLOW OUT Anywhere (v6) on all (out)
    ```

    Verify all open ports listening on non-localhost addresses have at least
one firewall rule.

    Lines identified by indexes 4 and 10 are firewall rules for new connections
on tcp port 22.
  "
  desc  "fix", "
    For each port identified in the audit which does not have a firewall rule
establish a proper rule for accepting inbound connections:

    ```
    # ufw allow in

    \t/
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
  tag cis_rid: "3.5.2.5"


  ufw_status = command('ss -4tuln && echo && echo && ufw status').stdout.strip

  if service('ufw').running? && service('ufw').enabled?
    describe "File '#{ufw_status}' \n Manually verification required.\nVAny ports that have been opened on non-loopback addresses need
firewall rules to govern traffic." do
      skip "File '#{ufw_status}' \n Manually verification required.\nAny ports that have been opened on non-loopback addresses need
firewall rules to govern traffic."
    end
  else
    describe service('ufw') do
      it { should be_running }
      it { should be_enabled }
    end
  end
end
