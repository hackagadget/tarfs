//===- lld/Core/Writer.h - Abstract File Format Interface -----------------===//
//
//                             The LLVM Linker
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLD_CORE_WRITER_H
#define LLD_CORE_WRITER_H

#include "lld/Core/LLVM.h"
#include <memory>
#include <vector>

namespace lld {
class ELFLinkingContext;
class File;
class LinkingContext;
class MachOLinkingContext;
class PECOFFLinkingContext;

/// \brief The Writer is an abstract class for writing object files, shared
/// library files, and executable files.  Each file format (e.g. ELF, mach-o,
/// PECOFF, etc) have a concrete subclass of Writer.
class Writer {
public:
  virtual ~Writer();

  /// \brief Write a file from the supplied File object
  virtual std::error_code writeFile(const File &linkedFile, StringRef path) = 0;

  /// \brief This method is called by Core Linking to give the Writer a chance
  /// to add file format specific "files" to set of files to be linked. This is
  /// how file format specific atoms can be added to the link.
  virtual void createImplicitFiles(std::vector<std::unique_ptr<File>> &) {}

protected:
  // only concrete subclasses can be instantiated
  Writer();
};

std::unique_ptr<Writer> createWriterELF(const ELFLinkingContext &);
std::unique_ptr<Writer> createWriterMachO(const MachOLinkingContext &);
std::unique_ptr<Writer> createWriterPECOFF(const PECOFFLinkingContext &);
std::unique_ptr<Writer> createWriterYAML(const LinkingContext &);
} // end namespace lld

#endif
