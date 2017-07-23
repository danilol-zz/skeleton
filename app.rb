require "sinatra/base"

class App < Sinatra::Base
  get '/' do
    "Hello ladies"
  end
end
