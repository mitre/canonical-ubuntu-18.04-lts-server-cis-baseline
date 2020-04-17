# encoding: UTF-8

control "C-1.7.1.3" do
  title "Ensure all AppArmor Profiles are in enforce or complain mode"
  desc  "AppArmor profiles define what resources applications are able to
access."
  desc  "rationale", "Security configuration requirements vary from site to
site. Some sites may mandate a policy that is stricter than the default policy,
which is perfectly acceptable. This item is intended to ensure that any
policies that exist on the system are activated."
  desc  "check", "
    Run the following command and verify that profiles are loaded, profiles are
in enforce or complain mode, and no processes are unconfined:

    ```
    # apparmor_status | grep profiles
    ```

    Review output and ensure that profiles are loaded, and in either enforce or
complain mode

    ```
    37 profiles are loaded.
    35 profiles are in enforce mode.
    2 profiles are in complain mode.
    4 processes have profiles defined.
    ```

    ```
    # apparmor_status | grep processes
    ```

    Review the output and ensure no processes are unconfined

    ```
    4 processes have profiles defined.
    4 processes are in enforce mode.
    0 processes are in complain mode.
    0 processes are unconfined but have a profile defined.
    ```
  "
  desc  "fix", "
    Run the following command to set all profiles to enforce mode:

    ```
    # aa-enforce /etc/apparmor.d/*
    ```

    **OR**

    Run the following command to set all profiles to complain mode:

    ```
    # aa-complain /etc/apparmor.d/*
    ```

    Any unconfined processes may need to have a profile created or activated
for them and then be restarted.
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
  tag cis_rid: "1.7.1.3"

  describe service('apparmor') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end


  num_loaded_profiles = inspec.command('apparmor_status | grep "profiles are loaded." | cut -f 1 -d " "').stdout.to_i
  num_enforced_profiles = inspec.command('apparmor_status | grep "profiles are in enforce mode." | cut -f 1 -d " "').stdout.to_i
  num_complain_profiles = inspec.command('apparmor_status | grep "profiles are in complain mode." | cut -f 1 -d " "').stdout.to_i
  num_enforced_and_complain_profiles = num_enforced_profiles + num_complain_profiles

  describe "AppArmor profiles #{num_loaded_profiles} are loaded" do
    it "and in either enforce (found: #{num_enforced_profiles}) or complain mode (found: #{num_complain_profiles})" do
      expect(num_enforced_and_complain_profiles).to eq(num_loaded_profiles)
    end
  end

  num_unconfigured_but_defined= inspec.command('apparmor_status | grep "are unconfined but have a profile defined." | cut -f 1 -d " "').stdout.to_i
  describe "#{num_unconfigured_but_defined} AppArmor Processes" do
    it "have profiles defined, but are unconfigured" do
      expect(num_unconfigured_but_defined).to eq(0)
    end
  end
  # are unconfined but have a profile defined.
end
