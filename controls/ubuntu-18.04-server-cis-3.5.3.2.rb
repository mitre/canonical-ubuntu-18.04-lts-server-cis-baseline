# encoding: UTF-8

control "C-3.5.3.2" do
  title "Ensure a table exists"
  desc  "Tables hold chains. Each table only has one address family and only
applies to packets of this family. Tables can have one of five families."
  desc  "rationale", "nftables doesn't have any default tables. Without a table
being build, nftables will not filter network traffic."
  desc  "check", "
    Run the following command to verify that a nftables table exists:

    ```
    # nft list tables
    ```

    Return should include a list of nftables:

    example:

    ```
    table inet filter
    ```
  "
  desc  "fix", "
    Run the following command to create a table in nftables

    ```
    # nft create table inet

    ```

    Example:

    ```
    # nft create table inet filter
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
  tag cis_rid: "3.5.3.2"

  nft_tables = command('nft list tables').stdout.strip

  if service('nftables').running? && service('nftables').enabled?
    describe "File '#{nft_tables}' \n Manually verification required.\n verify that a nftables table exists." do
      skip "File '#{nft_tables}' \n Manually verification required.\n Aerify that a nftables table exists."
    end
  else
    describe service('nftables') do
      it { should be_running }
      it { should be_enabled }
    end
  end
end



