//===--- HeaderGuard.cpp - clang-tidy -------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "HeaderGuard.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Lex/PPCallbacks.h"
#include "clang/Lex/Preprocessor.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/Path.h"

namespace clang::tidy::utils {

/// canonicalize a path by removing ./ and ../ components.
static std::string cleanPath(StringRef Path) {
  SmallString<256> Result = Path;
  llvm::sys::path::remove_dots(Result, true);
  return std::string(Result.str());
}

namespace {
class HeaderGuardPPCallbacks : public PPCallbacks {
public:
  HeaderGuardPPCallbacks(Preprocessor *PP, HeaderGuardCheck *Check)
      : PP(PP), Check(Check) {}

  void FileChanged(SourceLocation Loc, FileChangeReason Reason,
                   SrcMgr::CharacteristicKind FileType,
                   FileID PrevFID) override {
    // Record all files we enter. We'll need them to diagnose headers without
    // guards.
    SourceManager &SM = PP->getSourceManager();
    if (Reason == EnterFile && FileType == SrcMgr::C_User) {
      if (OptionalFileEntryRef FE =
              SM.getFileEntryRefForID(SM.getFileID(Loc))) {
        std::string FileName = cleanPath(FE->getName());
        Files[FileName] = *FE;
      }
    }
  }

  void Ifndef(SourceLocation Loc, const Token &MacroNameTok,
              const MacroDefinition &MD) override {
    if (MD)
      return;

    // Record #ifndefs that succeeded. We also need the Location of the Name.
    Ifndefs[MacroNameTok.getIdentifierInfo()] =
        std::make_pair(Loc, MacroNameTok.getLocation());
  }

  void MacroDefined(const Token &MacroNameTok,
                    const MacroDirective *MD) override {
    // Record all defined macros. We store the whole token to get info on the
    // name later.
    Macros.emplace_back(MacroNameTok, MD->getMacroInfo());
  }

  void Endif(SourceLocation Loc, SourceLocation IfLoc) override {
    // Record all #endif and the corresponding #ifs (including #ifndefs).
    EndIfs[IfLoc] = Loc;
  }

  void PragmaDirective(SourceLocation Loc,
                       PragmaIntroducerKind Introducer) override {
    SourceManager &SM = PP->getSourceManager();
    if (OptionalFileEntryRef FE = SM.getFileEntryRefForID(SM.getFileID(Loc))) {
      std::string FileName = cleanPath(FE->getName());

      if (!Files.contains(FileName)) {
        return;
      }
    }

    // Convert to a spelling location to handle macro expansions
    clang::SourceLocation SpellingLoc = SM.getSpellingLoc(Loc);

    // Get the line number and extract the line of text
    auto [fst, snd] = SM.getDecomposedLoc(SpellingLoc);
    clang::StringRef LineText = SM.getBufferData(fst);

    // Extract the line itself
    const char *LineStart = LineText.data() + SM.getFileOffset(SpellingLoc);
    const char *LineEnd = LineStart;
    while (*LineEnd != '\n' && *LineEnd != '\r' && *LineEnd != '\0')
      LineEnd++;
    clang::StringRef PragmaLine(LineStart, LineEnd - LineStart);

    if (PragmaLine.trim().equals("#pragma once")) {
      if (OptionalFileEntryRef FE = SM.getFileEntryRefForID(fst)) {
        std::string FileName = cleanPath(FE->getName());
        PragmaOncedFiles[FileName] = *FE;
      }
    }
  }

  void EndOfMainFile() override {
    // Now that we have all this information from the preprocessor, use it!
    SourceManager &SM = PP->getSourceManager();

    for (const auto &MacroEntry : Macros) {
      const MacroInfo *MI = MacroEntry.second;

      // We use clang's header guard detection. This has the advantage of also
      // emitting a warning for cases where a pseudo header guard is found but
      // preceded by something blocking the header guard optimization.
      if (!MI->isUsedForHeaderGuard())
        continue;

      OptionalFileEntryRef FE =
          SM.getFileEntryRefForID(SM.getFileID(MI->getDefinitionLoc()));
      std::string FileName = cleanPath(FE->getName());
      Files.erase(FileName);

      // See if we should check and fix this header guard.
      if (!Check->shouldFixHeaderGuard(FileName))
        continue;

      // Look up Locations for this guard.
      SourceLocation Ifndef =
          Ifndefs[MacroEntry.first.getIdentifierInfo()].second;
      SourceLocation Define = MacroEntry.first.getLocation();
      SourceLocation EndIf =
          EndIfs[Ifndefs[MacroEntry.first.getIdentifierInfo()].first];

      std::vector<FixItHint> FixIts;
      StringRef CurHeaderGuard =
          MacroEntry.first.getIdentifierInfo()->getName();
      if (Check->shouldUsePragmaOnce()) {
        checkPragmaOnceDefinition(Ifndef, Define, EndIf, CurHeaderGuard,
                                  FixIts);
        if (!FixIts.empty()) {
          Check->diag(Ifndef,
                      "header guard should be replaced with #pragma once")
              << FixIts;
        }
      } else {
        // If the macro Name is not equal to what we can compute, correct it in
        // the #ifndef and #define.
        std::string NewGuard = checkHeaderGuardDefinition(
            Ifndef, Define, EndIf, FileName, CurHeaderGuard, FixIts);

        // Now look at the #endif. We want a comment with the header guard. Fix
        // it at the slightest deviation.
        checkEndifComment(FileName, EndIf, NewGuard, FixIts);

        // Bundle all fix-its into one warning. The message depends on whether
        // we changed the header guard or not.
        if (!FixIts.empty()) {
          if (CurHeaderGuard != NewGuard) {
            Check->diag(Ifndef, "header guard does not follow preferred style")
                << FixIts;
          } else {
            Check->diag(EndIf, "#endif for a header guard should reference the "
                               "guard macro in a comment")
                << FixIts;
          }
        }
      }
    }

    // Emit warnings for headers that are missing guards.
    checkGuardlessHeaders();
    clearAllState();
  }

  bool wouldFixEndifComment(StringRef FileName, SourceLocation EndIf,
                            StringRef HeaderGuard,
                            size_t *EndIfLenPtr = nullptr) {
    if (!EndIf.isValid())
      return false;
    const char *EndIfData = PP->getSourceManager().getCharacterData(EndIf);
    size_t EndIfLen = std::strcspn(EndIfData, "\r\n");
    if (EndIfLenPtr)
      *EndIfLenPtr = EndIfLen;

    StringRef EndIfStr(EndIfData, EndIfLen);
    EndIfStr = EndIfStr.substr(EndIfStr.find_first_not_of("#endif \t"));

    // Give up if there's an escaped newline.
    size_t FindEscapedNewline = EndIfStr.find_last_not_of(' ');
    if (FindEscapedNewline != StringRef::npos &&
        EndIfStr[FindEscapedNewline] == '\\')
      return false;

    bool IsLineComment =
        EndIfStr.consume_front("//") ||
        (EndIfStr.consume_front("/*") && EndIfStr.consume_back("*/"));
    if (!IsLineComment)
      return Check->shouldSuggestEndifComment(FileName);

    return EndIfStr.trim() != HeaderGuard;
  }

  int getLineNumber(clang::SourceLocation loc) {
    SourceManager &SM = PP->getSourceManager();
    if (loc.isValid()) {
      if (loc.isMacroID()) {
        return SM.getPresumedLineNumber(SM.getExpansionLoc(loc));
      }
      return SM.getPresumedLineNumber(loc);
    }
    return -1;
  }

  clang::SourceRange getLineRange(int line, clang::SourceManager &sm,
                                  clang::FileID fileId) {
    // Get the start of the given line
    clang::SourceLocation startLoc = sm.translateLineCol(fileId, line, 1);

    // Try to get the start of the next line
    clang::SourceLocation endLoc = sm.translateLineCol(fileId, line + 1, 1);

    // If getting the start of the next line fails, assume end of the file
    if (endLoc.isInvalid()) {
      clang::SourceLocation lastLoc = sm.getLocForEndOfFile(fileId);
      endLoc = lastLoc.isValid() ? lastLoc : startLoc;
    } else {
      // Step back one character to stay on the current line
      endLoc = endLoc.getLocWithOffset(-1);
    }

    return clang::SourceRange(startLoc, endLoc);
  }

  void checkPragmaOnceDefinition(SourceLocation Ifndef, SourceLocation Define,
                                 SourceLocation EndIf, StringRef CurHeaderGuard,
                                 std::vector<FixItHint> &FixIts) {

    if (Ifndef.isValid()) {
      FixIts.push_back(FixItHint::CreateReplacement(
          CharSourceRange::getTokenRange(
              Ifndef.getLocWithOffset(-8),
              Define.getLocWithOffset(CurHeaderGuard.size())),
          "#pragma once"));

      const char *EndIfData = PP->getSourceManager().getCharacterData(EndIf);
      size_t EndIfLen = std::strcspn(EndIfData, "\r\n");
      FixIts.push_back(FixItHint::CreateRemoval(CharSourceRange::getTokenRange(
          EndIf.getLocWithOffset(-4), EndIf.getLocWithOffset(EndIfLen))));
    }
  }

  /// Look for header guards that don't match the preferred style. Emit
  /// fix-its and return the suggested header guard (or the original if no
  /// change was made.
  std::string checkHeaderGuardDefinition(SourceLocation Ifndef,
                                         SourceLocation Define,
                                         SourceLocation EndIf,
                                         StringRef FileName,
                                         StringRef CurHeaderGuard,
                                         std::vector<FixItHint> &FixIts) {
    std::string CPPVar = Check->getHeaderGuard(FileName, CurHeaderGuard);
    CPPVar = Check->sanitizeHeaderGuard(CPPVar);
    std::string CPPVarUnder = CPPVar + '_';

    // Allow a trailing underscore if and only if we don't have to change the
    // endif comment too.
    if (Ifndef.isValid() && CurHeaderGuard != CPPVar &&
        (CurHeaderGuard != CPPVarUnder ||
         wouldFixEndifComment(FileName, EndIf, CurHeaderGuard))) {
      FixIts.push_back(FixItHint::CreateReplacement(
          CharSourceRange::getTokenRange(
              Ifndef, Ifndef.getLocWithOffset(CurHeaderGuard.size())),
          CPPVar));
      FixIts.push_back(FixItHint::CreateReplacement(
          CharSourceRange::getTokenRange(
              Define, Define.getLocWithOffset(CurHeaderGuard.size())),
          CPPVar));
      return CPPVar;
    }
    return std::string(CurHeaderGuard);
  }

  /// Checks the comment after the #endif of a header guard and fixes it
  /// if it doesn't match \c HeaderGuard.
  void checkEndifComment(StringRef FileName, SourceLocation EndIf,
                         StringRef HeaderGuard,
                         std::vector<FixItHint> &FixIts) {
    size_t EndIfLen = 0;
    if (wouldFixEndifComment(FileName, EndIf, HeaderGuard, &EndIfLen)) {
      FixIts.push_back(FixItHint::CreateReplacement(
          CharSourceRange::getCharRange(EndIf,
                                        EndIf.getLocWithOffset(EndIfLen)),
          Check->formatEndIf(HeaderGuard)));
    }
  }

  /// Looks for files that were visited but didn't have a header guard.
  /// Emits a warning with fixits suggesting adding one.
  void checkGuardlessHeaders() {
    // Look for header files that didn't have a header guard. Emit a warning and
    // fix-its to add the guard.
    for (const auto &FE : Files) {
      if (Check->shouldUsePragmaOnce() &&
          PragmaOncedFiles.contains(FE.getKey())) {
        continue;
      }

      StringRef FileName = FE.getKey();
      if (!Check->shouldSuggestToAddHeaderGuard(FileName))
        continue;

      SourceManager &SM = PP->getSourceManager();
      FileID FID = SM.translateFile(FE.getValue());
      SourceLocation StartLoc = SM.getLocForStartOfFile(FID);
      if (StartLoc.isInvalid())
        continue;

      std::string CPPVar = Check->getHeaderGuard(FileName);
      CPPVar = Check->sanitizeHeaderGuard(CPPVar);
      std::string CPPVarUnder = CPPVar + '_'; // Allow a trailing underscore.
      // If there's a macro with a name that follows the header guard convention
      // but was not recognized by the preprocessor as a header guard there must
      // be code outside of the guarded area. Emit a plain warning without
      // fix-its.
      // FIXME: Can we move it into the right spot?
      bool SeenMacro = false;
      for (const auto &MacroEntry : Macros) {
        StringRef Name = MacroEntry.first.getIdentifierInfo()->getName();
        SourceLocation DefineLoc = MacroEntry.first.getLocation();
        if ((Name == CPPVar || Name == CPPVarUnder) &&
            SM.isWrittenInSameFile(StartLoc, DefineLoc)) {
          Check->diag(DefineLoc, "code/includes outside of area guarded by "
                                 "header guard; consider moving it");
          SeenMacro = true;
          break;
        }
      }

      if (SeenMacro)
        continue;

      if (Check->shouldUsePragmaOnce()) {
        Check->diag(StartLoc, "header is missing \"#pragma once\" header guard")
            << FixItHint::CreateInsertion(StartLoc, "#pragma once\n");
      } else {
        Check->diag(StartLoc, "header is missing header guard")
            << FixItHint::CreateInsertion(StartLoc, "#ifndef " + CPPVar +
                                                        "\n#define " + CPPVar +
                                                        "\n\n")
            << FixItHint::CreateInsertion(
                   SM.getLocForEndOfFile(FID),
                   Check->shouldSuggestEndifComment(FileName)
                       ? "\n#" + Check->formatEndIf(CPPVar) + "\n"
                       : "\n#endif\n");
      }
    }
  }

private:
  void clearAllState() {
    Macros.clear();
    Files.clear();
    PragmaOncedFiles.clear();
    Ifndefs.clear();
    EndIfs.clear();
  }

  std::vector<std::pair<Token, const MacroInfo *>> Macros;
  llvm::StringMap<const FileEntry *> Files;
  llvm::StringMap<const FileEntry *> PragmaOncedFiles;
  std::map<const IdentifierInfo *, std::pair<SourceLocation, SourceLocation>>
      Ifndefs;
  std::map<SourceLocation, SourceLocation> EndIfs;

  Preprocessor *PP;
  HeaderGuardCheck *Check;
};
} // namespace

void HeaderGuardCheck::storeOptions(ClangTidyOptions::OptionMap &Opts) {
  Options.store(Opts, "HeaderFileExtensions", RawStringHeaderFileExtensions);
  Options.store(Opts, "UsePragmaOnce", UsePragmaOnce);
}

void HeaderGuardCheck::registerPPCallbacks(const SourceManager &SM,
                                           Preprocessor *PP,
                                           Preprocessor *ModuleExpanderPP) {
  PP->addPPCallbacks(std::make_unique<HeaderGuardPPCallbacks>(PP, this));
}

std::string HeaderGuardCheck::sanitizeHeaderGuard(StringRef Guard) {
  // Only reserved identifiers are allowed to start with an '_'.
  return Guard.drop_while([](char C) { return C == '_'; }).str();
}

bool HeaderGuardCheck::shouldSuggestEndifComment(StringRef FileName) {
  return utils::isFileExtension(FileName, HeaderFileExtensions);
}

bool HeaderGuardCheck::shouldFixHeaderGuard(StringRef FileName) { return true; }

bool HeaderGuardCheck::shouldSuggestToAddHeaderGuard(StringRef FileName) {
  return utils::isFileExtension(FileName, HeaderFileExtensions);
}

std::string HeaderGuardCheck::formatEndIf(StringRef HeaderGuard) {
  return "endif // " + HeaderGuard.str();
}
bool HeaderGuardCheck::shouldUsePragmaOnce() { return UsePragmaOnce; }
} // namespace clang::tidy::utils
