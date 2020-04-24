# encoding: UTF-8

control "C-1.8.1.1" do
  title "Ensure message of the day is configured properly"
  desc  "The contents of the `/etc/motd` file are displayed to users after
login and function as a message of the day for authenticated users.

    Unix-based systems have typically displayed information about the OS
release and patch level upon logging in to the system. This information can be
useful to developers who are developing software for a particular OS platform.
If `mingetty(8)` supports the following options, they display operating system
information: `\\m` - machine architecture `\
` - operating system release `\\s` - operating system name `\\v` - operating
system version
  "
  desc  "rationale", "Warning messages inform users who are attempting to login
to the system of their legal status regarding the system and must include the
name of the organization that owns the system and any monitoring policies that
are in place. Displaying OS and patch level information in login banners also
has the side effect of providing detailed system information to attackers
attempting to target specific exploits of a system. Authorized users can easily
get this information by running the \" `uname -a` \" command once they have
logged in."
  desc  "check", "
    Run the following command and verify that the contents match site policy:

    ```
    # cat /etc/motd
    ```

    Run the following command and verify no results are returned:

    ```
    # grep -E -i -s \"(\\\\\\v|\\\\\|\\\\\\m|\\\\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e's/\"//g'))\" /etc/motd
    ```
  "
  desc "fix", "
    Edit the `/etc/motd` file with the appropriate contents according to your
site policy, remove any instances of `\\m` , `\
` , `\\s` , `\\v` or references to the `OS platform`

    OR

    If the motd is not used, this file can be removed.

    Run the following command to remove the motd file:

    ```
    # rm /etc/motd
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
  tag cis_rid: "1.8.1.1"

  describe command("grep '/etc/os-release' /etc/motd").stdout.strip.split("\n") do
    its('length') { should be < 1 }
  end

end
