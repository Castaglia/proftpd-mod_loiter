package ProFTPD::Tests::Modules::mod_loiter;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use File::Copy;
use File::Path qw(mkpath);
use File::Spec;
use IO::Handle;
use IO::Socket::INET;
use Time::HiRes qw(gettimeofday tv_interval usleep);

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  loiter_ftp => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  loiter_ftp_maxinstances => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  # XXX loiter_sftp
};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

sub loiter_ftp {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'loiter');

  my $loiter_msg = '"Go away, loiterer!"';
  my $loiter_tab = File::Spec->rel2abs("$tmpdir/loiter.tab");

  my $low_watermark = 1;
  my $high_watermark = 5;

  my $idle_timeout = 15;
  my $max_instances = 5;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'DEFAULT:10 lock:0 scoreboard:0 signal:0 loiter:20 loiter.shm:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',
    MaxInstances => $max_instances,
    TimeoutIdle => $idle_timeout,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_loiter.c' => {
        LoiterEngine => 'on',
        LoiterLog => $setup->{log_file},
        LoiterMessage => $loiter_msg,
        LoiterRules => "low $low_watermark high $high_watermark",
        LoiterTable => $loiter_tab,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow server to start up
      sleep(2);

      my $client_opts = {
        PeerHost => '127.0.0.1',
        PeerPort => $port,
        Proto => 'tcp',
        Type => SOCK_STREAM,
        Timeout => 30,
      };

      my $clients = [];

      # We expect at least 1 client to successfully connect, and at least
      # one client to fail to connect.
      my $count = $max_instances + 1;
      my $expected_max = $count - 1;
      my $expected_min = 1;

      for (my $i = 0; $i <= $count; $i++) {
        my $client = IO::Socket::INET->new(%$client_opts);
        unless ($client) {
          die("Can't connect to 127.0.0.1:$port: $!");
        }

        # Read the banner
        my $banner = <$client>;
        if ($ENV{TEST_VERBOSE}) {
          print STDOUT "# Received banner:\n$banner";
        }

        if ($banner !~ /^530/) {
          push(@$clients, $client);
        }
      }

      my $client_count = scalar(@$clients);
      $self->assert($client_count >= $expected_min &&
                    $client_count <= $expected_max,
        test_msg("Expected $expected_min <= $client_count <= $expected_max"));

      foreach my $client (@$clients) {
        my $cmd = "QUIT\r\n";
        if ($ENV{TEST_VERBOSE}) {
          print STDOUT "# Sending command: $cmd";
        }
        $client->print($cmd);
        $client->flush();

        my $resp = <$client>;
        if ($ENV{TEST_VERBOSE}) {
          print STDOUT "# Received response: $resp";
        }

        $client->close();
      }
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub loiter_ftp_maxinstances {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'loiter');

  my $loiter_msg = '"Go away, loiterer!"';
  my $loiter_tab = File::Spec->rel2abs("$tmpdir/loiter.tab");

  my $low_watermark = 1;
  my $high_watermark = 10;

  my $idle_timeout = 15;
  my $max_instances = 5;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'DEFAULT:10 lock:0 scoreboard:0 signal:0 loiter:20 loiter.shm:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',
    MaxInstances => $max_instances,
    TimeoutIdle => $idle_timeout,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_loiter.c' => {
        LoiterEngine => 'on',
        LoiterLog => $setup->{log_file},
        LoiterMessage => $loiter_msg,
        LoiterRules => "low $low_watermark high $high_watermark",
        LoiterTable => $loiter_tab,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow server to start up
      sleep(2);

      my $client_opts = {
        PeerHost => '127.0.0.1',
        PeerPort => $port,
        Proto => 'tcp',
        Type => SOCK_STREAM,
        Timeout => 30,
      };

      my $clients = [];

      # We expect at least 1 client to successfully connect, and at least
      # one client to fail to connect.
      my $count = $max_instances + 1;
      my $expected_max = $count - 1;
      my $expected_min = 1;

      for (my $i = 0; $i <= $count; $i++) {
        my $client = IO::Socket::INET->new(%$client_opts);
        unless ($client) {
          die("Can't connect to 127.0.0.1:$port: $!");
        }

        # Read the banner
        my $banner = <$client>;
        if ($ENV{TEST_VERBOSE}) {
          print STDOUT "# Received banner:\n$banner";
        }

        if ($banner !~ /^530/) {
          push(@$clients, $client);
        }
      }

      my $client_count = scalar(@$clients);
      $self->assert($client_count >= $expected_min &&
                    $client_count <= $expected_max,
        test_msg("Expected $expected_min <= $client_count <= $expected_max"));

      foreach my $client (@$clients) {
        my $cmd = "QUIT\r\n";
        if ($ENV{TEST_VERBOSE}) {
          print STDOUT "# Sending command: $cmd";
        }
        $client->print($cmd);
        $client->flush();

        my $resp = <$client>;
        if ($ENV{TEST_VERBOSE}) {
          print STDOUT "# Received response: $resp";
        }

        $client->close();
      }
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

1;
