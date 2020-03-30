# encoding: UTF-8

control "C-5.4.2" do
  title "Ensure system accounts are secured"
  desc  "There are a number of accounts provided with most distributions that
are used to manage applications and are not intended to provide an interactive
shell."
  desc  "rationale", "It is important to make sure that accounts that are not
being used by regular users are prevented from being used to provide an
interactive shell. By default, most distributions set the password field for
these accounts to an invalid string, but it is also recommended that the shell
field in the password file be set to the `nologin` shell. This prevents the
account from potentially being used to run any commands."
  desc  "check", "
    Run the following commands and verify no results are returned:

    ```
    awk -F: '($1!=\"root\" && $1!=\"sync\" && $1!=\"shutdown\" && $1!=\"halt\"
&& $1!~/^\\+/ && $3
  "
  desc  "fix", "
    Run the commands appropriate for your distribution:

    Set the shell for any accounts returned by the audit to nologin:

    ```
    # usermod -s $(which nologin)
    ```

    Lock any non root accounts returned by the audit:

    ```
    # usermod -L
    ```

    The following command will set all system accounts to a non login shell:

    ```
    awk -F: '($1!=\"root\" && $1!=\"sync\" && $1!=\"shutdown\" && $1!=\"halt\"
&& $1!~/^\\+/ && $3
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ["AC-2", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["16", "Rev_7"]
  tag cis_rid: "5.4.2"
end
