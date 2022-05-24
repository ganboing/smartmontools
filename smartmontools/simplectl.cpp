asm (".symver memcpy, memcpy@GLIBC_2.2.5");

#include "config.h"
#define __STDC_FORMAT_MACROS 1 // enable PRI* for C++

#include <errno.h>
#include <error.h>
#include <inttypes.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdexcept>
#include <getopt.h>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <ext/stdio_filebuf.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
//#include <sys/mman.h>
#endif

extern "C"
{
void *__wrap_memcpy(void *dest, const void *src, size_t n)
{
        return memcpy(dest, src, n);
}
}

#include "json.h"
#include "atacmds.h"
#include "ataprint.h"
#include "knowndrives.h"
#include "nlohmann/json.hpp"

#define PERC_EXE "/opt/lsi/perccli/perccli"

json jglb;

inline std::string cppfmt(const char *fmt, ...)
{
  std::string ret;
  va_list vl;
  va_start(vl, fmt);
  int len = vsnprintf(nullptr, 0, fmt, vl);
  va_end(vl);
  assert(len >= 0);
  if (!len)
      return ret;
  ret.resize(len);
  assert(!ret.empty());
  va_start(vl, fmt);
  vsprintf(&ret.front(), fmt, vl);
  va_end(vl);
  return ret;
}

void jout(const char *fmt, ...){
  va_list ap;

  va_start(ap,fmt);
  vfprintf(stdout, fmt, ap);
  va_end(ap);
  return;
}

void pout(const char *fmt, ...){
  va_list ap;

  va_start(ap,fmt);
  vfprintf(stdout, fmt, ap);
  va_end(ap);
  return;
}

static void perc_check_cmd_status(const nlohmann::json& j_cmds) {
  auto& j_desc = j_cmds.at("Description");
  auto desc = j_desc.get<std::string>();
  auto& j_status = j_cmds.at("Status");
  auto status = j_status.get<std::string>();
  if (status == "Success") {
    return;
  } else if (status == "Failure") {
    error(1, 0, "perc cmd failed: %s", desc.c_str());
  } else {
    error(1, 0, "perc cmd failed (%s): %s", status.c_str(), desc.c_str());
  }
}

static std::vector<uint8_t> perc_hex_to_bin(const std::string& hex_str) {
  std::vector<uint8_t> ret;
  size_t consumed;
  uint8_t byte;

  const char *p = hex_str.c_str();
  while(sscanf(p, "%hhx %zn", &byte, &consumed) == 1) {
    p += consumed;
    ret.emplace_back(byte);
  }
  return ret;
}

static ata_identify_device perc_raw_identify(unsigned card, unsigned enclosure, unsigned disk) {
  std::string cmdline = cppfmt("%s /c%d /e%d /s%d show all j", PERC_EXE, card, enclosure, disk);
  FILE *pipe = popen(cmdline.c_str(), "re");
  std::unique_ptr<FILE, decltype(&fclose)> _mf(pipe, fclose);
  if (!pipe) {
    error(1, errno, "popen(%s... failed", cmdline.c_str());
  }
  __gnu_cxx::stdio_filebuf<char> filebuf(pipe, std::ios::in);
  nlohmann::json j_resp;
  if (!(std::istream(&filebuf) >> j_resp)) {
    error(1, 0, "failed to parse response json from %s", cmdline.c_str());
  }
  auto& j_call = j_resp.at("Controllers");
  if (j_call.size() != 1) {
    error(1, 0, "None or multiple controllers found");
  }
  auto& j_c0 = j_call.at(0);
  auto& j_cmds = j_c0.at("Command Status");
  perc_check_cmd_status(j_cmds);
  std::string tag = cppfmt("Drive /c%d/e%d/s%d - Detailed Information", card, enclosure, disk);
  auto& data = j_c0.at("Response Data").at(tag).at("Inquiry Data");
  auto bin = perc_hex_to_bin(data.get<std::string>());
  size_t to_copy = std::min(sizeof(ata_identify_device), bin.size());
  ata_identify_device ret = {};
  memcpy(&ret, bin.data(), to_copy);
  return ret;
}

ata_smart_values perc_raw_smart(unsigned card, unsigned enclosure, unsigned disk) {
  std::string cmdline = cppfmt("%s /c%d /e%d /s%d show smart j", PERC_EXE, card, enclosure, disk);
  FILE *pipe = popen(cmdline.c_str(), "re");
  std::unique_ptr<FILE, decltype(&fclose)> _mf(pipe, fclose);
  if (!pipe) {
    error(1, errno, "popen(%s... failed", cmdline.c_str());
  }
  __gnu_cxx::stdio_filebuf<char> filebuf(pipe, std::ios::in);
  nlohmann::json j_resp;
  if (!(std::istream(&filebuf) >> j_resp)) {
    error(1, 0, "failed to parse response json from %s", cmdline.c_str());
  }
  auto& j_call = j_resp.at("Controllers");
  if (j_call.size() != 1) {
    error(1, 0, "None or multiple controllers found");
  }
  auto& j_c0 = j_call.at(0);
  auto& j_cmds = j_c0.at("Command Status");
  perc_check_cmd_status(j_cmds);
  std::string tag = cppfmt("Smart Data Info /c%d/e%d/s%d", card, enclosure, disk);
  auto& data = j_c0.at("Response Data").at(tag);
  auto bin = perc_hex_to_bin(data.get<std::string>());
  if (bin.size() != sizeof(ata_smart_values)) {
    error(1, 0, "SMART data returned is not 512 bytes long");
  }
  ata_smart_values ret;
  memcpy(&ret, bin.data(), bin.size());
  return ret;
}

int main(int argc, char **argv)
{
  if (argc < 4) {
     fprintf(stderr, "usage: %s <Controller> <Enclosure> <Disk>\n", argv[0]);
     return 1;
  }
  unsigned card = atoi(argv[1]), enclosure = atoi(argv[2]), disk = atoi(argv[3]);
  ata_identify_device identify = perc_raw_identify(card, enclosure, disk);
  ata_smart_values smart_vals = perc_raw_smart(card, enclosure, disk);
  init_drive_database(true);
  ata_vendor_attr_defs vendor_defs = {};
  firmwarebug_defs fwbug_defs = {};
  std::string dbversion;
  const drive_settings * dbentry = lookup_drive_apply_presets(&identify,
          vendor_defs, fwbug_defs, dbversion);
  //showallpresets();
  char model[40+1], serial[20+1], firmware[8+1];
  ata_format_id_string(model, identify.model, sizeof(model)-1);
  ata_format_id_string(serial, identify.serial_no, sizeof(serial)-1);
  ata_format_id_string(firmware, identify.fw_rev, sizeof(firmware)-1);
  if (!dbentry)
    fprintf(stderr, "Device: %s-%s/%s, not found in smartd database%s%s.\n",
            model, serial, firmware,
            (!dbversion.empty() ? " " : ""),
            (!dbversion.empty() ? dbversion.c_str() : ""));
  else {
    fprintf(stderr, "Device: %s-%s/%s, found in smartd database%s%s%s%s\n",
            model, serial, firmware,
            (!dbversion.empty() ? " " : ""),
            (!dbversion.empty() ? dbversion.c_str() : ""),
            (*dbentry->modelfamily ? ": " : "."),
            (*dbentry->modelfamily ? dbentry->modelfamily : ""));
    if (*dbentry->warningmsg)
      fprintf(stderr, "Device: %s-%s/%s, WARNING: %s\n",
              model, serial, firmware,
              dbentry->warningmsg);
  }
  PrintGeneralSmartValues(&smart_vals, &identify, fwbug_defs);
  ata_smart_thresholds_pvt thresh = {};
  PrintSmartAttribWithThres(&smart_vals, &thresh, vendor_defs, 0, 0, 0);
}
