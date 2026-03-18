#!/usr/bin/env perl
use strict;
use warnings;
use IO::Socket::INET;
use JSON::PP qw(encode_json decode_json);
use File::Path qw(make_path);
use POSIX qw(strftime);
use Digest::SHA qw(sha1_hex);

my $host = $ENV{VSAT_BIND} // '127.0.0.1';
my $port = $ENV{VSAT_PORT} // 8080;
my $root = '.';
my $public_dir = "$root/public";
my $data_dir = "$root/data";
my $log_dir = "$root/logs";
my $state_file = "$data_dir/state.json";
my $request_log = "$log_dir/requests.log";
my $auth_log = "$log_dir/auth.log";

make_path($public_dir, $data_dir, $log_dir);
bootstrap_state() unless -e $state_file;

my $server = IO::Socket::INET->new(
    LocalAddr => $host,
    LocalPort => $port,
    Proto     => 'tcp',
    Listen    => 10,
    Reuse     => 1,
) or die "Unable to bind $host:$port: $!";

print "VSAT decoy listening on http://$host:$port\n";

while (my $client = $server->accept()) {
    $client->autoflush(1);
    eval { handle_client($client) };
    close $client;
}

sub handle_client {
    my ($client) = @_;
    my $request_line = <$client>;
    return unless defined $request_line;
    $request_line =~ s/\r?\n$//;
    my ($method, $path, $proto) = split /\s+/, $request_line, 3;
    return unless $method && $path;

    my %headers;
    while (my $line = <$client>) {
        $line =~ s/\r?\n$//;
        last if $line eq '';
        my ($name, $value) = split /:\s*/, $line, 2;
        next unless defined $name;
        $headers{lc $name} = $value // '';
    }

    my $content_length = $headers{'content-length'} // 0;
    my $body = '';
    if ($content_length =~ /^\d+$/ && $content_length > 0) {
        read($client, $body, $content_length);
    }

    my ($uri, $query_string) = split /\?/, $path, 2;
    $uri = normalize_path($uri // '/');

    my $cookie_header = $headers{'cookie'} // '';
    my %cookies = map {
        my ($k, $v) = split /=/, $_, 2;
        defined $k ? ($k => ($v // '')) : ()
    } map { s/^\s+|\s+$//gr } split /;\s*/, $cookie_header;

    my $session_id = $cookies{session_id} // '';
    my $remote = eval { $client->peerhost } // 'unknown';
    my $state = load_state();
    my $now = iso_now();
    my $user = session_user($state, $session_id);

    log_line($request_log, encode_json({
        ts => $now,
        remote => $remote,
        method => $method,
        path => $uri,
        query => parse_form($query_string // ''),
        user => $user,
        agent => ($headers{'user-agent'} // ''),
    }));

    if ($uri eq '/api/login' && $method eq 'POST') {
        my $payload = parse_json_body($body);
        my $username = trim($payload->{username} // '');
        my $password = $payload->{password} // '';
        my $new_session = create_session($state, $username || 'operator');
        save_state($state);
        log_line($auth_log, encode_json({
            ts => $now,
            remote => $remote,
            username => $username,
            password => $password,
            session_id => $new_session,
            result => 'accepted',
        }));
        send_json($client, 200, {
            ok => JSON::PP::true,
            operator => $username || 'operator',
            redirect => '/dashboard',
        }, ["Set-Cookie: session_id=$new_session; Path=/; HttpOnly; SameSite=Lax"]);
        return;
    }

    if ($uri eq '/api/logout' && $method eq 'POST') {
        if ($session_id && exists $state->{sessions}{$session_id}) {
            delete $state->{sessions}{$session_id};
            save_state($state);
        }
        send_json($client, 200, { ok => JSON::PP::true }, [
            "Set-Cookie: session_id=deleted; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
        ]);
        return;
    }

    if ($uri eq '/api/status' && $method eq 'GET') {
        my $status = build_status($state);
        save_state($state);
        send_json($client, 200, {
            authenticated => $user ? JSON::PP::true : JSON::PP::false,
            operator => $user // '',
            status => $status,
            profile => $state->{profile},
            terminals => $state->{terminals},
            wan => $state->{wan},
            logs => {
                events => $state->{events},
                commands => $state->{command_log},
            },
        });
        return;
    }

    if ($uri eq '/api/config/network' && $method eq 'POST') {
        return reject_unauth($client) unless $user;
        my $payload = parse_json_body($body);
        $state->{wan}{targetIp} = trim($payload->{targetIp} // $state->{wan}{targetIp});
        $state->{wan}{mask} = trim($payload->{mask} // $state->{wan}{mask});
        $state->{wan}{gateway} = trim($payload->{gateway} // $state->{wan}{gateway});
        prepend_command($state, {
            ts => $now,
            operator => $user,
            action => 'network-profile-write',
            detail => "Updated modem management network to $state->{wan}{targetIp}/$state->{wan}{mask}",
        });
        append_event($state, {
            ts => $now,
            level => 'notice',
            code => 'CFG-204',
            message => 'Terminal network configuration updated',
        });
        save_state($state);
        send_json($client, 200, { ok => JSON::PP::true, wan => $state->{wan} });
        return;
    }

    if ($uri eq '/api/config/antenna' && $method eq 'POST') {
        return reject_unauth($client) unless $user;
        my $payload = parse_json_body($body);
        $state->{profile}{trackingMode} = trim($payload->{trackingMode} // $state->{profile}{trackingMode});
        $state->{profile}{satelliteName} = trim($payload->{satelliteName} // $state->{profile}{satelliteName});
        $state->{profile}{profileName} = trim($payload->{profileName} // $state->{profile}{profileName});
        prepend_command($state, {
            ts => $now,
            operator => $user,
            action => 'antenna-profile-write',
            detail => "Tracking mode set to $state->{profile}{trackingMode}",
        });
        append_event($state, {
            ts => $now,
            level => 'notice',
            code => 'ANT-117',
            message => 'Antenna profile updated',
        });
        save_state($state);
        send_json($client, 200, { ok => JSON::PP::true, profile => $state->{profile} });
        return;
    }

    if ($uri eq '/api/command' && $method eq 'POST') {
        return reject_unauth($client) unless $user;
        my $payload = parse_json_body($body);
        my $command = trim($payload->{command} // '');
        prepend_command($state, {
            ts => $now,
            operator => $user,
            action => 'cli-command',
            detail => $command || 'blank command',
        });
        append_event($state, {
            ts => $now,
            level => 'warning',
            code => 'CLI-310',
            message => $command ? "Uncommitted command staged: $command" : 'Blank terminal command received',
        });
        save_state($state);
        send_json($client, 200, {
            ok => JSON::PP::true,
            echo => $command,
            output => [
                'command mode: simulated',
                'result: pending modem synchronization',
                'note: writes are isolated to the decoy environment',
            ],
        });
        return;
    }

    if ($uri eq '/' || $uri eq '/dashboard') {
        send_file($client, "$public_dir/index.html", 'text/html; charset=utf-8');
        return;
    }

    if ($uri =~ m{^/assets/([A-Za-z0-9._/-]+)$}) {
        my $asset = $1;
        my $file = "$public_dir/assets/$asset";
        if (-f $file) {
            my $content_type = mime_type($file);
            send_file($client, $file, $content_type);
        } else {
            send_plain($client, 404, "Not found\n");
        }
        return;
    }

    send_plain($client, 404, "Not found\n");
}

sub bootstrap_state {
    my $state = {
        profile => {
            profileName => 'North Atlantic Backup',
            satelliteName => 'KA-NORDIC-17',
            trackingMode => 'Auto',
            firmware => '2.4.18-hb',
            uptimeHours => 4182,
        },
        wan => {
            targetIp => '172.18.44.15',
            mask => '255.255.255.0',
            gateway => '172.18.44.1',
            qosProfile => 'Fleet-Priority-2',
        },
        terminals => [
            {
                name => 'Above Deck Unit',
                status => 'Tracking',
                temperature => 41,
                azimuth => 182.4,
                elevation => 38.9,
            },
            {
                name => 'Below Deck Unit',
                status => 'Operational',
                temperature => 35,
                azimuth => 0,
                elevation => 0,
            }
        ],
        telemetry => {
            rxDbm => -62.3,
            txDbm => 11.2,
            cNo => 14.8,
            ber => '2.4e-6',
            gps => '59.4370N / 24.7536E',
            heading => 71,
            pitch => 1.3,
            roll => 0.8,
            packets => 17424011,
        },
        events => [
            { ts => iso_now(), level => 'info', code => 'SYS-001', message => 'Decoy modem stack initialized' },
            { ts => iso_now(), level => 'notice', code => 'NET-084', message => 'WAN carrier synchronized' },
            { ts => iso_now(), level => 'info', code => 'ANT-045', message => 'Antenna stabilized within target window' },
        ],
        command_log => [
            { ts => iso_now(), operator => 'system', action => 'boot-sequence', detail => 'Operational profile restored from persistent store' },
        ],
        sessions => {},
    };
    save_state($state);
}

sub build_status {
    my ($state) = @_;
    my $loop = navigation_loop_sample(time);
    $state->{telemetry}{rxDbm} = sprintf('%.1f', -62.4 + 0.7 * $loop->{sea});
    $state->{telemetry}{txDbm} = sprintf('%.1f', 11.1 + 0.5 * $loop->{swell});
    $state->{telemetry}{cNo} = sprintf('%.1f', 14.7 + 0.4 * $loop->{sea});
    $state->{telemetry}{heading} = $loop->{heading};
    $state->{telemetry}{pitch} = sprintf('%.1f', $loop->{pitch});
    $state->{telemetry}{roll} = sprintf('%.1f', $loop->{roll});
    $state->{telemetry}{gps} = format_gps($loop->{lat}, $loop->{lon});
    $state->{telemetry}{packets} += 320 + int(280 * (1 + $loop->{sea}));
    $state->{profile}{uptimeHours} += 1 if int(time / 3600) > $state->{profile}{uptimeHours};
    return $state->{telemetry};
}

sub navigation_loop_sample {
    my ($epoch) = @_;
    my $loop_seconds = 300;
    my $offset = $epoch % $loop_seconds;
    my $theta = 2 * 3.14159265358979 * ($offset / $loop_seconds);

    # A short repeating harbor-exit style track centered off Tallinn roads.
    my $base_lat = 59.5042;
    my $base_lon = 24.7038;
    my $lat = $base_lat + 0.0120 * sin($theta) + 0.0018 * sin(3 * $theta);
    my $lon = $base_lon + 0.0210 * cos($theta - 0.22) + 0.0025 * sin(2 * $theta);

    my $dlat = 0.0120 * cos($theta) + 0.0054 * cos(3 * $theta);
    my $dlon = -0.0210 * sin($theta - 0.22) + 0.0050 * cos(2 * $theta);
    my $heading = atan2_deg($dlon, $dlat);

    my $sea = sin($theta - 0.35);
    my $swell = sin(2 * $theta + 0.4);

    return {
        lat => $lat,
        lon => $lon,
        heading => sprintf('%.0f', $heading),
        pitch => 1.4 + 0.6 * $swell + 0.2 * sin(5 * $theta),
        roll => 0.8 + 1.0 * $sea + 0.2 * cos(4 * $theta),
        sea => $sea,
        swell => $swell,
    };
}

sub atan2_deg {
    my ($y, $x) = @_;
    my $angle = atan2($y, $x) * 180 / 3.14159265358979;
    $angle += 360 if $angle < 0;
    return $angle;
}

sub format_gps {
    my ($lat, $lon) = @_;
    my $lat_hemisphere = $lat >= 0 ? 'N' : 'S';
    my $lon_hemisphere = $lon >= 0 ? 'E' : 'W';
    return sprintf('%.4f%s / %.4f%s', abs($lat), $lat_hemisphere, abs($lon), $lon_hemisphere);
}

sub create_session {
    my ($state, $user) = @_;
    my $session_id = sha1_hex(join ':', $user, time, rand(), $$);
    $state->{sessions}{$session_id} = {
        user => $user,
        issued_at => iso_now(),
    };
    return $session_id;
}

sub session_user {
    my ($state, $session_id) = @_;
    return unless $session_id;
    return unless exists $state->{sessions}{$session_id};
    return $state->{sessions}{$session_id}{user};
}

sub prepend_command {
    my ($state, $item) = @_;
    unshift @{$state->{command_log}}, $item;
    splice @{$state->{command_log}}, 12 if @{$state->{command_log}} > 12;
}

sub append_event {
    my ($state, $item) = @_;
    unshift @{$state->{events}}, $item;
    splice @{$state->{events}}, 12 if @{$state->{events}} > 12;
}

sub load_state {
    open my $fh, '<', $state_file or die "Unable to read state: $!";
    local $/;
    my $json = <$fh>;
    close $fh;
    return decode_json($json);
}

sub save_state {
    my ($state) = @_;
    open my $fh, '>', $state_file or die "Unable to write state: $!";
    print {$fh} encode_json($state);
    close $fh;
}

sub parse_json_body {
    my ($body) = @_;
    return {} unless defined $body && length $body;
    my $decoded = eval { decode_json($body) };
    return $decoded && ref $decoded eq 'HASH' ? $decoded : {};
}

sub parse_form {
    my ($value) = @_;
    return {} unless defined $value && length $value;
    my %pairs;
    for my $pair (split /&/, $value) {
        my ($k, $v) = split /=/, $pair, 2;
        $k = url_decode($k // '');
        $v = url_decode($v // '');
        $pairs{$k} = $v;
    }
    return \%pairs;
}

sub normalize_path {
    my ($uri) = @_;
    $uri =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
    $uri =~ s/\0//g;
    $uri =~ s#//+#/#g;
    return $uri;
}

sub url_decode {
    my ($text) = @_;
    $text =~ tr/+/ /;
    $text =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
    return $text;
}

sub trim {
    my ($text) = @_;
    $text //= '';
    $text =~ s/^\s+//;
    $text =~ s/\s+$//;
    return $text;
}

sub iso_now {
    return strftime('%Y-%m-%dT%H:%M:%SZ', gmtime());
}

sub log_line {
    my ($file, $line) = @_;
    open my $fh, '>>', $file or die "Unable to append $file: $!";
    print {$fh} $line . "\n";
    close $fh;
}

sub send_file {
    my ($client, $file, $content_type) = @_;
    open my $fh, '<', $file or do {
        send_plain($client, 404, "Not found\n");
        return;
    };
    binmode $fh;
    local $/;
    my $content = <$fh>;
    close $fh;
    send_response($client, 200, 'OK', $content_type, $content, []);
}

sub send_plain {
    my ($client, $status, $content) = @_;
    my %text = (
        401 => 'Unauthorized',
        404 => 'Not Found',
    );
    send_response($client, $status, ($text{$status} // 'OK'), 'text/plain; charset=utf-8', $content, []);
}

sub send_json {
    my ($client, $status, $data, $extra_headers) = @_;
    $extra_headers ||= [];
    my %text = (
        200 => 'OK',
        401 => 'Unauthorized',
    );
    send_response($client, $status, ($text{$status} // 'OK'), 'application/json; charset=utf-8', encode_json($data), $extra_headers);
}

sub reject_unauth {
    my ($client) = @_;
    send_json($client, 401, {
        ok => JSON::PP::false,
        error => 'Authentication required',
    });
}

sub send_response {
    my ($client, $status, $reason, $content_type, $content, $extra_headers) = @_;
    my @headers = (
        "HTTP/1.1 $status $reason",
        "Content-Type: $content_type",
        'Connection: close',
        'Cache-Control: no-store',
        'X-Frame-Options: DENY',
        'X-Content-Type-Options: nosniff',
        'Server: VSAT-Decoy/0.1',
        "Content-Length: " . length($content),
        @$extra_headers,
        '',
        '',
    );
    print {$client} join("\r\n", @headers);
    print {$client} $content;
}

sub mime_type {
    my ($file) = @_;
    return 'text/css; charset=utf-8' if $file =~ /\.css$/;
    return 'application/javascript; charset=utf-8' if $file =~ /\.js$/;
    return 'image/svg+xml' if $file =~ /\.svg$/;
    return 'text/html; charset=utf-8' if $file =~ /\.html$/;
    return 'text/plain; charset=utf-8';
}
