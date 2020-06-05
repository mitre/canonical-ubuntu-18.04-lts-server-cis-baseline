# encoding: UTF-8

control "C-3.5.3.3" do
  title "Ensure base chains exist"
  desc  "Chains are containers for rules. They exist in two kinds, base chains
and regular chains. A base chain is an entry point for packets from the
networking stack, a regular chain may be used as jump target and is used for
better rule organization."
  desc  "rationale", "If a base chain doesn't exist with a hook for input,
forward, and delete, packets that would flow through those chains will not be
touched by nftables."
  desc  "check", "
    Run the following commands and verify that base chains exist for `INPUT`,
`FORWARD`, and `OUTPUT`.

    ```
    # nft list ruleset | grep 'hook input'

    type filter hook input priority 0;
    ```

    ```
    # nft list ruleset | grep 'hook forward'

    type filter hook forward priority 0;
    ```

    ```
    # nft list ruleset | grep 'hook output'

    type filter hook output priority 0;
    ```
  "
  desc  "fix", "
    Run the following command to create the base chains:

    ```
    # nft create chain inet

      { type filter hook  priority 0 \\; }
    ```

    Example:

    ```
    # nft create chain inet filter input { type filter hook input priority 0
\\; }

    # nft create chain inet filter forward { type filter hook forward priority
0 \\; }

    # nft create chain inet filter output { type filter hook output priority 0
\\; }
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
  tag cis_rid: "3.5.3.3"

  nft_tables = command('nft list ruleset').stdout.strip.split(/[\n|;]/)

  if service('nftables').running? && service('nftables').enabled?
    describe nft_tables do
      it { should match '\s+type\s+filter\s+hook\s+input\s+priority\s+0' }
      it { should match 'type filter hook forward priority 0' }
      it { should match 'type filter hook output priority 0' }
    end
  else
    describe service('nftables') do
      it { should be_running }
      it { should be_enabled }
    end
  end
end
