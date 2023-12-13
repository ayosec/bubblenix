#include "options.h"

#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int generate_bpf(struct Options *options);

static void usage(char *cmd, int status) {
  fprintf(stderr, "Usage: %s: [-o, --output output] [-c, --allow-clone3] [-f, --allow-fsync] [-t, --allow-tracing]\n", cmd);
  exit(status);
}

static void parse_opts(struct Options *options, int argc, char **argv) {
  char *cmd = strdupa(argv[0]);

  struct option opts[] = {
    {"allow-clone3", no_argument, 0, 'c'},
    {"allow-fsync", no_argument, 0, 'f'},
    {"allow-tracing", no_argument, 0, 't'},
    {"help", no_argument, 0, 'h'},
    {"output", required_argument, 0, 'o'},
  };

  while(1) {
    switch(getopt_long(argc, argv, "cftho:", opts, NULL)) {
      case -1:
        if (optind != argc) {
          fprintf(stderr, "Invalid option: %s\n", argv[optind]);
          usage(cmd, 1);
        }

        return;

      case 'c':
        options->allow_clone3 = true;
        break;

      case 'f':
        options->allow_fsync = true;
        break;

      case 't':
        options->allow_tracing = true;
        break;

      case 'o':
        options->output = fopen(optarg, "w");

        if (options->output == NULL) {
          perror(optarg);
          exit(2);
        }

        break;

      case 'h':
        usage(cmd, 0);
        break;

      default:
        usage(cmd, 1);
    }
  }
}

int main(int argc, char **argv) {
  struct Options options = {
    .allow_clone3 = false,
    .allow_fsync = false,
    .allow_tracing = false,
    .output = stdout
  };

  parse_opts(&options, argc, argv);

  if (isatty(fileno(options.output))) {
    fprintf(stderr, "The output must not be a TTY\n");
    return 1;
  }

  return generate_bpf(&options) ? 0 : 3;
}
