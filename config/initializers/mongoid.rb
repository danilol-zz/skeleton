require 'mongoid'

Mongoid.load!("#{File.join(File.dirname(__FILE__), '..', 'mongoid.yml')}")

if defined?(PhusionPassenger)
  PhusionPassenger.on_event(:starting_worker_process) do |forked|
    Mongoid.default_session.disconnect if forked
  end
end
