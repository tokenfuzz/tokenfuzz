/*
 * rbundle_cli.cpp — command-line front end for the RBF decoder.
 *
 * Reads an RBF stream from the file named on the command line and decodes it.
 * This is the entry point an audit harness drives: it turns a file of bytes
 * into a single rbundle::decode() call over the exact input length.
 */
#include "rbundle.hpp"

#include <cstdio>
#include <vector>

int main(int argc, char **argv) {
  if (argc != 2) {
    std::fprintf(stderr, "usage: %s stream-file\n", argv[0]);
    return 2;
  }

  std::FILE *fp = std::fopen(argv[1], "rb");
  if (fp == nullptr) {
    std::fprintf(stderr, "could not read input\n");
    return 2;
  }

  std::vector<std::uint8_t> data;
  std::uint8_t chunk[4096];
  std::size_t got;
  while ((got = std::fread(chunk, 1, sizeof(chunk), fp)) > 0) {
    data.insert(data.end(), chunk, chunk + got);
  }
  std::fclose(fp);

  int fields = rbundle::decode(data.data(), data.size());
  if (fields < 0) {
    std::fprintf(stderr, "not an RBF stream\n");
    return 1;
  }
  std::printf("decoded %d field(s)\n", fields);
  return 0;
}
