# encoding: UTF-8

control "C-5.4.5" do
  title "Ensure default user shell timeout is 900 seconds or less"
  desc  "The default `TMOUT` determines the shell timeout for users. The TMOUT
value is measured in seconds."
  desc  "rationale", "Having no timeout value associated with a shell could
allow an unauthorized user access to another user's shell session (e.g. user
walks away from their computer and doesn't lock the screen). Setting a timeout
value at least reduces the risk of this happening."
  desc  "check", "
    Run the following commands and verify all TMOUT lines returned are 900 or
less and at least one exists in each file.

    ```
    # grep -E -i
\"^\\s*(\\S+\\s+)*TMOUT=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9])\\s*(\\S+\\s*)*(\\s+#.*)?$\"
/etc/bash.bashrc

    readonly TMOUT=900 ; export TMOUT
    ```

    ```
    # grep -E -i
\"^\\s*(\\S+\\s+)*TMOUT=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9])\\s*(\\S+\\s*)*(\\s+#.*)?$\"
/etc/profile /etc/profile.d/*.sh

    readonly TMOUT=900 ; export TMOUT
    ```
  "
  desc "fix", "
    Edit the `/etc/bashrc`, `/etc/profile` and `/etc/profile.d/*.sh` files (and
the appropriate files for any other shell supported on your system) and add or
edit any TMOUT parameters in accordance with site policy:

    ```
    readonly TMOUT=900 ; export TMOUT
    ```

    **Note:** setting the value to `readonly` prevents unwanted modification
during runtime.
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ["AC-11", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["16.11", "Rev_7"]
  tag cis_rid: "5.4.5"
end
