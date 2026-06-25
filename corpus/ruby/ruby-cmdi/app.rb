require "sinatra"

# GET /ping?host=... with a planted command-injection sink.
get "/ping" do
  host = params["host"]
  # VULN: user-controlled host interpolated into a shell command.
  `ping -c 1 #{host}`
end
