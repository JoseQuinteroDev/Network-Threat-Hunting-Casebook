##! Flags likely DNS tunnels: one client resolving many unique, long, high-entropy subdomains under a
##! single base domain within one hour. Same logic and thresholds as tools/dns_profile.py (means are
##! taken over unique subdomains).
##!
##! Windows are fixed hours computed from packet timestamps, so the result is the same when reading a
##! capture and on live traffic. (SumStats epochs were tried first: they never closed while reading a
##! capture with Zeek 9.0, so a tunnel only produced one notice per run.)
##!
##! Usage:  zeek -C -r capture.pcap local detections/zeek/dns-tunnel-detect.zeek
##! Output: notice.log entries with note DNSTunnel::Suspected_Tunnel, at most one per client, base
##!         domain and hour.

@load base/frameworks/notice
@load base/protocols/dns

module DNSTunnel;

export {
	redef enum Notice::Type += { Suspected_Tunnel };

	const window = 1hr &redef;
	## Fixed before looking at any capture (see methodology.md).
	const min_unique_subdomains = 50 &redef;
	const min_mean_length = 20.0 &redef;
	const min_mean_entropy = 3.0 &redef;
	## Names under these suffixes are ignored (reverse lookups, mDNS).
	const ignored_suffixes = /\.(in-addr\.arpa|ip6\.arpa|local)$/ &redef;
}

type Bucket: record {
	subdomains: set[string];
	total_length: count &default=0;
	total_entropy: double &default=0.0;
	notified: bool &default=F;
};

## Keyed by client, base domain and window number; old windows expire on their own.
global buckets: table[addr, string, count] of Bucket &create_expire=2hr;

## Approximates the registrable domain with the last two labels. The Python tool uses the full
## public suffix list, so the two can differ for names under suffixes such as co.uk.
function base_domain(name: string): string
	{
	local labels = split_string(name, /\./);
	local n = |labels|;
	if ( n < 3 )
		return name;
	return fmt("%s.%s", labels[n - 2], labels[n - 1]);
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string)
	{
	local name = to_lower(query);
	if ( ignored_suffixes in name )
		return;
	local base = base_domain(name);
	if ( |name| <= |base| + 1 )
		return;
	local subdomain = sub_bytes(name, 1, |name| - |base| - 1);
	local client = c$id$orig_h;
	# floor() first: double_to_count() rounds, which would move the window boundary to hh:30.
	local w = double_to_count(floor(time_to_double(network_time()) / interval_to_double(window)));

	if ( [client, base, w] !in buckets )
		buckets[client, base, w] = Bucket($subdomains=set());
	local b = buckets[client, base, w];
	if ( b$notified || subdomain in b$subdomains )
		return;

	add b$subdomains[subdomain];
	b$total_length += |subdomain|;
	b$total_entropy += find_entropy(gsub(subdomain, /\./, ""))$entropy;

	local n = |b$subdomains|;
	if ( n < min_unique_subdomains )
		return;
	local mean_length = (b$total_length + 0.0) / n;
	local mean_entropy = b$total_entropy / n;
	if ( mean_length < min_mean_length || mean_entropy < min_mean_entropy )
		return;

	b$notified = T;
	NOTICE([$note=Suspected_Tunnel,
	        $conn=c,
	        $sub=base,
	        $msg=fmt("%s: %d unique subdomains within %s, mean length %.1f, mean entropy %.2f bits/char",
	                 base, n, window, mean_length, mean_entropy),
	        $identifier=cat(client, base, w)]);
	}
