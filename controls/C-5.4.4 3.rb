# encoding: UTF-8

control "C-5.4.4" do
  title "Ensure default user umask is 027 or more restrictive"
  desc  "The default `umask` determines the permissions of files created by
users. The user creating the file has the discretion of making their files and
directories readable by others via the chmod command. Users who wish to allow
their files and directories to be readable by others by default may choose a
different default umask by inserting the `umask` command into the standard
shell configuration files ( `.profile` , `.bashrc` , etc.) in their home
directories."
  desc  "rationale", "Setting a very secure default value for `umask` ensures
that users make a conscious choice about their file permissions. A default
`umask` setting of `077` causes files and directories created by users to not
be readable by any other user on the system. A `umask` of `027` would make
files and directories readable by users in the same Unix group, while a `umask`
of `022` would make files readable by every user on the system."
  desc  "check", "
    Run the following commands and verify all umask lines returned are 027 or
more restrictive.

    ```
    # grep \"umask\" /etc/bash.bashrc

    umask 027
    ```

    ```
    # grep \"umask\" /etc/profile /etc/profile.d/*.sh

    umask 027
    ```
  "
  desc "fix", "
    Edit the `/etc/bash.bashrc`, `/etc/profile` and `/etc/profile.d/*.sh` files
(and the appropriate files for any other shell supported on your system) and
add or edit any umask parameters as follows:

    ```
    umask 027
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
  tag nist: ["AC-3 (3)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["14.6", "Rev_7"]
  tag cis_rid: "5.4.4"
end
