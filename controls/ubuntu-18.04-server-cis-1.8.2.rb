# encoding: UTF-8

control "C-1.8.2" do
  title "Ensure GDM login banner is configured"
  desc  "GDM is the GNOME Display Manager which handles graphical login for
GNOME based systems."
  desc  "rationale", "Warning messages inform users who are attempting to login
to the system of their legal status regarding the system and must include the
name of the organization that owns the system and any monitoring policies that
are in place."
  desc  "check", "
    If GDM is installed on the system verify that
`/etc/gdm3/greeter.dconf-defaults` file exists and contains the following:

    ```
    [org/gnome/login-screen]
    banner-message-enable=true
    banner-message-text=''
    ```
  "
  desc "fix", "
    Edit or create the file `/etc/gdm3/greeter.dconf-defaults` and add the
following:

    ```
    [org/gnome/login-screen]
    banner-message-enable=true
    banner-message-text='Authorized uses only. All activity may be monitored
and reported.'
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
  tag cis_rid: "1.8.2"
end
