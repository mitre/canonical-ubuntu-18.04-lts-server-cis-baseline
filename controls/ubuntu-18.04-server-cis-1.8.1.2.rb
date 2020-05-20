# encoding: UTF-8

control "C-1.8.1.2" do
  title "Ensure local login warning banner is configured properly"
  desc  "The contents of the `/etc/issue` file are displayed to users prior to
login for local terminals.

    Unix-based systems have typically displayed information about the OS
release and patch level upon logging in to the system. This information can be
useful to developers who are developing software for a particular OS platform.
If `mingetty(8)` supports the following options, they display operating system
information: `\\m` - machine architecture `\
` - operating system release `\\s` - operating system name `\\v` - operating
system version - or the operating system's name
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
    # cat /etc/issue
    ```

    Run the following command and verify no results are returned:

    ```
    # grep -E -i \"(\\\\\\v|\\\\\
|\\\\\\m|\\\\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e
's/\"//g'))\" /etc/issue
    ```
  "
  desc "fix", "
    Edit the `/etc/issue` file with the appropriate contents according to your
site policy, remove any instances of `\\m` , `\
` , `\\s` , `\\v` or references to the `OS platform`

    ```
    # echo \"Authorized uses only. All activity may be monitored and
reported.\" > /etc/issue
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
  tag cis_rid: "1.8.1.2"

  banner_message_text_cli = input('banner_message_text_cli')
  banner_message_text_cli_limited = input('banner_message_text_cli_limited')

  clean_banner = banner_message_text_cli.gsub(%r{[\r\n\s]}, '')
  clean_banner_limited = banner_message_text_cli_limited.gsub(%r{[\r\n\s]}, '')
  banner_file = file("/etc/issue")
  banner_missing = !banner_file.exist?

  describe 'The banner text is not set because /etc/issue does not exist' do
    subject { banner_missing }
    it { should be false }
  end if banner_missing

  banner_message = banner_file.content.gsub(%r{[\r\n\s]}, '')
  describe.one do
    describe 'The banner text should match the standard banner' do
      subject { banner_message }
      it { should cmp clean_banner }
    end
    describe 'The banner text should match the limited banner' do
      subject { banner_message }
      it{should cmp clean_banner_limited }
    end
  end if !banner_missing


banner_text = file('/etc/issue').content.gsub(%r{[\r\n\s]}, '')

describe "Banner text" do
  subject { banner_text }
  it { should eq attribute('banner_text').gsub(%r{[\r\n\s]}, '') }
end

  end