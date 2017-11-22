-------------------------------------------------------------------------------
-- Example chisel that shows how to send metrics to the sysdig cloud backend
-------------------------------------------------------------------------------
description = "Monitors a single log file or a set of log files, reporting the rate of occurrences of a provided term.";
short_description = "Log Watcher.";
category = "Logs";
		   
-- Argument list
args =
{
	{
		name = "filespattern",
		description = "All the files whose name contains the string specified in this argument will be watched.",
		argtype = "string",
		optional = true
	},
	{
		name = "term",
		description = "This is the string that will be matched against the log lines. Lines that include this term will be counted in the metric.",
		argtype = "string",
		optional = true
	},
	{
		name = "fdtype",
		description = "File descriptor type, same syntax of sysdig's fd.type.",
		argtype = "string",
		optional = true
	},
	{
		name = "metricname",
		description = "Statsd metric name.",
		argtype = "string",
		optional = true
	}
}

-- Imports and globals
require "common"
local nevents = 0
local filespattern
local term
local fbuf
local metric_name
local fdtype

function on_set_arg(name, val)
	if name == "filespattern" then
		filespattern = val
		return true
	elseif name == "term" then
		term = val
		return true
	elseif name == "fdtype" then
		fdtype = val
		return true
	elseif name == "metricname" then
		metric_name = val
		return true
	end

	return true
end

-- Initialization callback. Same as in regular chisels.
function on_init()
	if filespattern == nil or term == nil then
		sysdig.log("error starting the Log Watcher chisel: one of the arguments is missing", "warning")
		return false
	end

	if fdtype == nil then
		fdtype = "file"
	end

	if metric_name == nil then
		sanitized_term = string.gsub(term, "[^A-Za-z0-9]", "_")
		sanitized_filespattern = string.gsub(filespattern, "[^A-Za-z0-9]", "_")
		metric_name = "logwatcher." .. sanitized_filespattern .. "." .. sanitized_term
	end

	local filter = "fd.type=" .. fdtype .. " and evt.is_io_write=true and fd.name contains " .. filespattern .. " and evt.buffer contains '" .. term .. "'"

	chisel.set_filter(filter)

	-- Increase the snaplen a bit so we have more chanches to capture the term
	sysdig.set_snaplen(250)

	sysdig.log("starting log watcher. filespattern=" .. filespattern .. ", term=" .. term .. ", fdtype=" .. fdtype, "info")

	return true
end

-- Event parsing callback. Same as in regular chisels.
function on_event()
	nevents = nevents + 1
	return true
end

-- This function is onvoked by the sysdig cloud agent every time it's time to 
-- generate a new sample, which happens once a second.
-- This is where the chisel can add its own metrics to the sample that goes to
-- the sysdig cloud backend, using the push_metric() function.
-- The metrics pushed here will appear as statsd metrics in the sysdig cloud
-- user interface. 
function on_end_of_sample()
	-- Push our counter to the sysdig cloud backend
	sysdig.push_metric(metric_name, -- This is the metric name, as it will appear in the sysdig cloud UI
		nevents,                  -- This is the metric value. The sysdig cloud interface will let you 
		                          -- choose how to aggregate these values in time and for machine groups.
		{}                        -- This argument is optional and contains a list of tags that you can
		                          -- associate to this metric and that the sysdig cloud UI will let you
								  -- use for segmentation. Here you can put a process name, a user name,
								  -- a protocol ID or anything else you want.
	)
	
	nevents = 0

	return true
end
