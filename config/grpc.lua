
observer = {}

observer.event = function(e)
  grpc:observe(e, "localhost:50051")
end

return observer

