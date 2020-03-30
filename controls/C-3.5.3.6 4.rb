# encoding: UTF-8

control "C-3.5.3.6" do
  title "Ensure default deny firewall policy"
  desc  "Base chain policy is the default verdict that will be applied to
packets reaching the end of the chain."
  desc  "rationale", "
    There are two policies: accept (Default) and drop. If the policy is set to
`accept`, the firewall will accept any packet that is not configured to be
denied and the packet will continue transversing the network stack.

    It is easier to white list acceptable usage than to black list unacceptable
usage.
  "
  desc  "check", "
    Run the following commands and verify that base chains contain a policy of
`DROP`.

    ```
    # nft list ruleset | grep 'hook input'

    type filter hook input priority 0; policy drop;
    ```

    ```
    # nft list ruleset | grep 'hook forward'

    type filter hook forward priority 0; policy drop;
    ```

    ```
    # nft list ruleset | grep 'hook output'

    type filter hook output priority 0; policy drop;
    ```
  "
  desc  "fix", "
    Run the following command for the base chains with the input, forward, and
output hooks to implement a default DROP policy:

    ```
    # nft chain

      { policy drop \\; }
    ```

    Example:

    ```
    # nft chain inet filter input { policy drop \\; }

    # nft chain inet filter forward { policy drop \\; }

    # nft chain inet filter output { policy drop \\; }
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
  tag cis_rid: "3.5.3.6"
end
