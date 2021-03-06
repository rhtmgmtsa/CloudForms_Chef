=begin
-------------------------------------------------------------------------------
   Copyright 2017 Red Hat

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
-------------------------------------------------------------------------------
=end
def log(level, msg, update_message = false)
  $evm.log(level, "#{msg}")
  @task.message = msg if @task && (update_message || level == 'error')
end

def call_chef(cmd, timeout=20)
  # unset the variables for knife
  pre_cmd = "unset GEM_HOME GEM_PATH IRBRC MY_RUBY_HOME"

  require 'linux_admin'
  require 'timeout'
  begin
    Timeout::timeout(timeout) {
      log(:info, "Executing [#{cmd}] with timeout of #{timeout} seconds")
      result = LinuxAdmin::Common.run("#{pre_cmd};#{cmd}")
      log(:info, "success?: #{result.success?}")
      log(:info, "exit_status: #{result.exit_status}") unless result.exit_status.blank?
      log(:info, "output: #{result.output}")
      log(:info, "error: #{result.error}") unless result.error.blank?
      return result
    }
  rescue => timeout
    log(:error, "Error executing chef: #{timeout.class} #{timeout} #{timeout.backtrace.join("\n")}")
    return false
  end
end

# basic retry logic
def retry_method(retry_time=1.minute)
  log(:info, "Sleeping for #{retry_time} seconds")
  $evm.root['ae_result'] = 'retry'
  $evm.root['ae_retry_interval'] = retry_time
  exit MIQ_OK
end

# process_tags - Dynamically create categories and tags
def process_tags( category, category_description, single_value, tag, tag_description )
  # Convert to lower case and replace all non-word characters with underscores
  category_name = category.to_s.downcase.gsub(/\W/, '_')
  tag_name = tag.to_s.downcase.gsub(/\W/, '_')
  tag_name = tag.gsub(/:/, '_')
  log(:info, "Converted category name:<#{category_name}> Converted tag name: <#{tag_name}>")
  # if the category exists else create it
  unless $evm.execute('category_exists?', category_name)
    log(:info, "Category <#{category_name}> doesn't exist, creating category")
    $evm.execute('category_create', :name => category_name, :single_value => single_value, :description => "#{category_description}")
  end
  # if the tag exists else create it
  unless $evm.execute('tag_exists?', category_name, tag_name)
    log(:info, "Adding new tag <#{tag_name}> description <#{tag_description}> in Category <#{category_name}>")
    $evm.execute('tag_create', category_name, :name => tag_name, :description => "#{tag_description}")
  end
end

def get_chef_environment_name(ws_values={})
  chef_environment = $evm.object['chef_environment']
  chef_environment ||= $evm.root['dialog_chef_environment']
  if @task
    chef_environment = @task.get_tags[:chef_environment] ||
      ws_values[:chef_environment] ||
      @task.get_option(:chef_environment)
  end

  chef_environment ||= "_default"
  log(:info, "chef_environment: #{chef_environment}")
  return chef_environment
end

def get_chef_node_name
  if @task
    chef_node_name = @task.get_option(:vm_target_hostname)
  end
  chef_node_name ||= @vm.name
  log(:info, "chef_node_name: #{chef_node_name}")
  return chef_node_name
end

begin
  $evm.root.attributes.sort.each { |k, v| log(:info, "Root:<$evm.root> Attribute - #{k}: #{v}")}

  @task = $evm.root['miq_provision']
  @vm = $evm.root['vm']

  chef_bootstrap_attribute = "CHEF Bootstrapped"

  bootstrapped = $evm.get_state_var(chef_bootstrap_attribute)

  chef_environment = get_chef_environment_name
  chef_node_name = get_chef_node_name

  if bootstrapped =~ (/(true|t|yes|y|1)$/i)
    exists_cmd  = "/usr/bin/knife node show #{chef_node_name}"
    node_exists = call_chef(exists_cmd, 120)
    if node_exists.success?  
      delete_cmd  = "/usr/bin/knife node delete #{chef_node_name} "
      delete_cmd += "-E #{chef_environment} -y -F json "

      delete_result = call_chef(delete_cmd, 300)
      if delete_result.success?
        log(:info, "Successfully deleted Chef node #{chef_node_name}", true)
        @vm.custom_set(chef_bootstrap_attribute, nil)
        @vm.tag_unassign("chef_bootstrapped/true") rescue nil
      else
        log(:error, "Unable to delete Chef node #{chef_node_name}", true)
        raise "Exiting due to chef delete node failure"
      end
    else
      log(:info, "Chef Client doesn't exist: #{chef_node_name}")
      exit MIQ_OK
    end
  end

rescue => err
  log(:error, "[#{err}]\n#{err.backtrace.join("\n")}")
  exit MIQ_STOP
end
