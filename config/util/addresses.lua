
local module = {}

module.get_address = function(context, lst, cls, is_src)

  local par = context:get_parent()
  if par then
    module.get_address(par, lst, cls, is_src)
  end

  if is_src then
    tcls, addr = context:get_src_addr()
  else
    tcls, addr = context:get_dest_addr()
  end

  if tcls == cls then
    table.insert(lst, addr)
  end

end

-- Gets the stack of addresses on the src/dest side of a context.
module.get_stack = function(context, is_src)
  local par = context:get_parent()
  local addrs

  if par then
    if is_src then
      addrs = module.get_stack(par, true)
    else
      addrs = module.get_stack(par, false)
    end
  else
    addrs = {}
  end

  local cls, addr
  if is_src then
    cls, addr = context:get_src_addr()
  else
    cls, addr = context:get_dest_addr()
  end

  if not (addr == "") then
    addrs[#addrs + 1] = { protocol = cls, address = addr }
  end

  return addrs
end

return module

