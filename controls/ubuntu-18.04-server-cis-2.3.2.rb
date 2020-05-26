# encoding: UTF-8

control "C-2.3.2" do
  title "Ensure rsh client is not installed"
  desc  "The `rsh` package contains the client commands for the rsh services."
  desc  "rationale", "These legacy clients contain numerous security exposures
and have been replaced with the more secure SSH package. Even if the server is
removed, it is best to ensure the clients are also removed to prevent users
from inadvertently attempting to use these commands and therefore exposing
their credentials. Note that removing the `rsh` package removes the clients for
`rsh` , `rcp` and `rlogin` ."
  desc  "check", "
    Verify `rsh` is not installed. Use the following command to provide the
needed information:

    ```
    dpkg -s rsh-client
    ```
  "
  desc "fix", "
    Uninstall `rsh`:

    ```
    apt remove rsh-client
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
  tag nist: ["IA-2 (1)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["4.5", "Rev_7"]
  tag cis_rid: "2.3.2"

  describe package('rsh-client') do
    it { should_not be_installed }
  end
end
