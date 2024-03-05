//===--- IncludeCleanerCheckXLAB.cpp - clang-tidy
//-----------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "IncludeCleanerCheckXLAB.h"
#include "../ClangTidyCheck.h"
#include "../ClangTidyDiagnosticConsumer.h"
#include "../ClangTidyOptions.h"
#include "../utils/OptionsUtils.h"
#include "clang-include-cleaner/Analysis.h"
#include "clang-include-cleaner/IncludeSpeller.h"
#include "clang-include-cleaner/Record.h"
#include "clang-include-cleaner/Types.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclBase.h"
#include "clang/AST/ExprCXX.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/FileEntry.h"
#include "clang/Basic/LLVM.h"
#include "clang/Basic/LangOptions.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/Format/Format.h"
#include "clang/Lex/HeaderSearchOptions.h"
#include "clang/Lex/Preprocessor.h"
#include "clang/Tooling/Core/Replacement.h"
#include "clang/Tooling/Inclusions/HeaderIncludes.h"
#include "clang/Tooling/Inclusions/StandardLibrary.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/Regex.h"
#include <clang/AST/RecursiveASTVisitor.h>
#include <optional>
#include <string>
#include <vector>

using namespace clang::ast_matchers;

namespace clang::tidy::misc {
    namespace {
        struct MissingIncludeInfo {
            include_cleaner::SymbolReference SymRef;
            include_cleaner::Header Missing;
        };
    } // namespace

    IncludeCleanerCheckXLAB::IncludeCleanerCheckXLAB(StringRef Name,
                                                     ClangTidyContext* Context)
        : ClangTidyCheck(Name, Context),
          IgnoreHeaders(utils::options::parseStringList(
              Options.getLocalOrGlobal("IgnoreHeaders", ""))),
          OnlySpecificHeaders(utils::options::parseStringList(
              Options.getLocalOrGlobal("OnlySpecificHeaders", ""))),
          DeduplicateFindings(
              Options.getLocalOrGlobal("DeduplicateFindings", true)),
          SkipRemove(Options.getLocalOrGlobal("SkipRemove", false)),
          SkipInsert(Options.getLocalOrGlobal("SkipInsert", false)),
          EnableOnlySpecificHeaders(
              Options.getLocalOrGlobal("EnableOnlySpecificHeaders", false)) {
        for (const auto&Header: IgnoreHeaders) {
            if (!llvm::Regex{Header}.isValid())
                configurationDiag("Invalid ignore headers regex '%0'") << Header;
            std::string HeaderSuffix{Header.str()};
            if (!Header.ends_with("$"))
                HeaderSuffix += "$";
            IgnoreHeadersRegex.emplace_back(HeaderSuffix);
        }
        for (const auto&Header: OnlySpecificHeaders) {
            if (!llvm::Regex{Header}.isValid())
                configurationDiag("Invalid ignore headers regex '%0'") << Header;
            std::string HeaderSuffix{Header.str()};
            if (!Header.ends_with("$"))
                HeaderSuffix += "$";
            OnlySpecificHeadersRegex.emplace_back(HeaderSuffix);
        }
    }

    void IncludeCleanerCheckXLAB::storeOptions(ClangTidyOptions::OptionMap&Opts) {
        Options.store(Opts, "IgnoreHeaders",
                      utils::options::serializeStringList(IgnoreHeaders));
        Options.store(Opts, "OnlySpecificHeaders",
                      utils::options::serializeStringList(OnlySpecificHeaders));
        Options.store(Opts, "DeduplicateFindings", DeduplicateFindings);
        Options.store(Opts, "SkipRemove", SkipRemove);
        Options.store(Opts, "SkipInsert", SkipInsert);
        Options.store(Opts, "EnableOnlySpecificHeaders", EnableOnlySpecificHeaders);
    }

    bool IncludeCleanerCheckXLAB::isLanguageVersionSupported(
        const LangOptions&LangOpts) const {
        return !LangOpts.ObjC;
    }

    void IncludeCleanerCheckXLAB::registerMatchers(MatchFinder* Finder) {
        // Loop through all declarations in main TU
        Finder->addMatcher(translationUnitDecl().bind("top"), this);

        // Find all VTK pointer dereferences
        Finder->addMatcher(
            cxxMemberCallExpr(
                on(has(declRefExpr(to(cxxMethodDecl(ofClass(
                    allOf(isDerivedFrom("vtkObjectBase"), unless(isImplicit())))))))))
            .bind("vtkObjectBaseCall"),
            this);
    }

    void IncludeCleanerCheckXLAB::registerPPCallbacks(
        const SourceManager&SM, Preprocessor* PP, Preprocessor* ModuleExpanderPP) {
        PP->addPPCallbacks(RecordedPreprocessor.record(*PP));
        this->PP = PP;
        RecordedPI.record(*PP);
    }

    bool IncludeCleanerCheckXLAB::shouldIgnore(const include_cleaner::Header&H) {
        const auto GetName = [](const include_cleaner::Header&h) {
            switch (h.kind()) {
                case include_cleaner::Header::Standard:
                    return h.standard().name();
                case include_cleaner::Header::Verbatim:
                    return h.verbatim().trim("<>\"");
                case include_cleaner::Header::Physical:
                    return h.physical().getFileEntry().tryGetRealPathName();
            }
            return StringRef{};
        };
        auto res = llvm::any_of(IgnoreHeadersRegex, [&H](const llvm::Regex&R) {
            switch (H.kind()) {
                case include_cleaner::Header::Standard:
                    // We don't trim angle brackets around standard library headers
                    // deliberately, so that they are only matched as <vector>, otherwise
                    // having just `.*/vector` might yield false positives.
                    return R.match(H.standard().name());
                case include_cleaner::Header::Verbatim:
                    return R.match(H.verbatim().trim("<>\""));
                case include_cleaner::Header::Physical:
                    return R.match(H.physical().getFileEntry().tryGetRealPathName());
            }
            llvm_unreachable("Unknown Header kind.");
        });

        //llvm::outs() << "should ignore: " << GetName(H) << ": " << res << '\n';
        return res;
    }

    bool IncludeCleanerCheckXLAB::shouldInclude(const include_cleaner::Header&H) {
        if (!EnableOnlySpecificHeaders) {
            return true;
        }
        const auto GetName = [](const include_cleaner::Header&h) {
            switch (h.kind()) {
                case include_cleaner::Header::Standard:
                    return h.standard().name();
                case include_cleaner::Header::Verbatim:
                    return h.verbatim().trim("<>\"");
                case include_cleaner::Header::Physical:
                    return h.physical().getFileEntry().tryGetRealPathName();
            }
            return StringRef{};
        };

        auto res = llvm::any_of(OnlySpecificHeadersRegex, [&H](const llvm::Regex&R) {
            switch (H.kind()) {
                case include_cleaner::Header::Standard:
                    // We don't trim angle brackets around standard library headers
                    // deliberately, so that they are only matched as <vector>, otherwise
                    // having just `.*/vector` might yield false positives.
                    return R.match(H.standard().name());
                case include_cleaner::Header::Verbatim:
                    return R.match(H.verbatim().trim("<>\""));
                case include_cleaner::Header::Physical:
                    return R.match(H.physical().getFileEntry().tryGetRealPathName());
            }
            llvm_unreachable("Unknown Header kind.");
        });
        //llvm::outs() << "should include: " << GetName(H) << ": " << res << '\n';
        return res;
    }

    void IncludeCleanerCheckXLAB::check(const MatchFinder::MatchResult&Result) {
        const SourceManager* SM = Result.SourceManager;
        const FileEntry* MainFile = SM->getFileEntryForID(SM->getMainFileID());
        llvm::DenseSet<const include_cleaner::Include *> Used;
        std::vector<MissingIncludeInfo> Missing;
        llvm::SmallVector<Decl *> MainFileDecls;
        llvm::SmallVector<std::pair<Decl*, SourceLocation>> ForcedDecls;
        for (Decl* D: Result.Nodes.getNodeAs<TranslationUnitDecl>("top")->decls()) {
            if (!SM->isWrittenInMainFile(SM->getExpansionLoc(D->getLocation())))
                continue;
            // FIXME: Filter out implicit template specializations.
            MainFileDecls.push_back(D);
        }

        class MemberExprVisitor : public RecursiveASTVisitor<MemberExprVisitor> {
        public:
            explicit MemberExprVisitor(ASTContext* context,
                                       llvm::SmallVector<Decl *>&VEC, llvm::SmallVector<std::pair<Decl*, SourceLocation>>&VEC2)
                : MainFileDecls(VEC), ForcedDecls(VEC2), Context(context),
                  SM(Context->getSourceManager()) {
            }

            bool VisitCXXMemberCallExpr(CXXMemberCallExpr* Call) {
                if (!SM.isWrittenInMainFile(Call->getExprLoc())) {
                    return true;
                }
                CXXMethodDecl* MethodDecl = Call->getMethodDecl();
                //llvm::outs() << "MethodDecl: " << MethodDecl->getName() << '\n';
                if (MethodDecl) {
                    CXXRecordDecl* ClassDecl = MethodDecl->getParent();
                    //llvm::outs() << "ClassDecl: " << ClassDecl->getName() << '\n';
                    if (ClassDecl) {
                        // Check if the class is derived from vtkObjectBase.
                        for (auto BaseSpecifier: ClassDecl->bases()) {
                            CXXRecordDecl* BaseClassDecl = BaseSpecifier.getType()->getAsCXXRecordDecl();
                            //llvm::outs() << "BaseClassDecl: " << BaseClassDecl->getName() << '\n';
                            if (BaseClassDecl) {
                                if (BaseClassDecl->getQualifiedNameAsString() ==
                                    "vtkObjectBase") {
                                    // llvm::outs() << "Found vtkObjectBase kind: " << ClassDecl->getName() << " " <<
                                    //         ClassDecl->getLocation().printToString(SM) << '\n';
                                    ForcedDecls.push_back({ClassDecl, Call->getExprLoc()});
                                }
                            }
                        }
                    }
                }
                return true;
            }

        private:
            llvm::SmallVector<Decl *>&MainFileDecls;
            llvm::SmallVector<std::pair<Decl*, SourceLocation>>&ForcedDecls;

            ASTContext* Context;
            SourceManager&SM;
        };
        MemberExprVisitor visitor(Result.Context, MainFileDecls, ForcedDecls);
        visitor.TraverseDecl(Result.Context->getTranslationUnitDecl());
        // llvm::outs() << "Result: " << res << '\n';

        llvm::DenseSet<include_cleaner::Symbol> SeenSymbols;
        OptionalDirectoryEntryRef ResourceDir =
                PP->getHeaderSearchInfo().getModuleMap().getBuiltinDir();

        // llvm::outs() << "Found declarations: \n";
        // for(const auto d : MainFileDecls) {
        //     llvm::outs() <<
        //     d->getLocation().printToString(Result.Context->getSourceManager()) <<
        //     '\n';
        // }

        const auto pProcessDecl = [&](const include_cleaner::SymbolReference&Ref,
                                      llvm::ArrayRef<include_cleaner::Header> Providers) {
            if (DeduplicateFindings && !SeenSymbols.insert(Ref.Target).second)
                return;
            bool Satisfied = false;
            for (const include_cleaner::Header&H: Providers) {
                if (H.kind() == include_cleaner::Header::Physical &&
                    (H.physical() == MainFile ||
                     H.physical().getDir() == ResourceDir)) {
                    Satisfied = true;
                    continue;
                }

                for (const include_cleaner::Include* I:
                     RecordedPreprocessor.Includes.match(H)) {
                    Used.insert(I);
                    Satisfied = true;
                }
            }

            auto pTypeCheck = [&](const include_cleaner::SymbolReference&Ref) -> bool {
                return Ref.RT == include_cleaner::RefType::Explicit || Ref.RT == include_cleaner::RefType::Forced;
            };

            if (!Satisfied && !Providers.empty() &&
                pTypeCheck(Ref) &&
                !shouldIgnore(Providers.front()) &&
                shouldInclude(Providers.front())) {

                Missing.push_back({Ref, Providers.front()});
            }
        };

        walkUsedForced(ForcedDecls, RecordedPreprocessor.MacroReferences, &RecordedPI,
                       *PP,
                       [&](const include_cleaner::SymbolReference&Ref,
                           llvm::ArrayRef<include_cleaner::Header> Providers) {
                           pProcessDecl(Ref, Providers);
                       });
        walkUsed(MainFileDecls, RecordedPreprocessor.MacroReferences, &RecordedPI,
                 *PP,
                 [&](const include_cleaner::SymbolReference&Ref,
                     llvm::ArrayRef<include_cleaner::Header> Providers) {
                     pProcessDecl(Ref, Providers);
                 });

        std::vector<const include_cleaner::Include *> Unused;
        for (const include_cleaner::Include&I:
             RecordedPreprocessor.Includes.all()) {
            if (Used.contains(&I) || !I.Resolved || I.Resolved->getDir() == ResourceDir)
                continue;
            if (RecordedPI.shouldKeep(*I.Resolved))
                continue;
            // Check if main file is the public interface for a private header. If so
            // we shouldn't diagnose it as unused.
            if (auto PHeader = RecordedPI.getPublic(*I.Resolved); !PHeader.empty()) {
                PHeader = PHeader.trim("<>\"");
                // Since most private -> public mappings happen in a verbatim way, we
                // check textually here. This might go wrong in presence of symlinks or
                // header mappings. But that's not different than rest of the places.
                if (getCurrentMainFile().ends_with(PHeader))
                    continue;
            }
            auto StdHeader = tooling::stdlib::Header::named(
                I.quote(), PP->getLangOpts().CPlusPlus
                               ? tooling::stdlib::Lang::CXX
                               : tooling::stdlib::Lang::C);
            if (StdHeader && (shouldIgnore(*StdHeader) || !shouldInclude(*StdHeader)))
                continue;
            if (shouldIgnore(*I.Resolved) || !shouldInclude(*I.Resolved))
                continue;
            Unused.push_back(&I);
        }

        llvm::StringRef Code = SM->getBufferData(SM->getMainFileID());
        auto FileStyle =
                format::getStyle(format::DefaultFormatStyle, getCurrentMainFile(),
                                 format::DefaultFallbackStyle, Code,
                                 &SM->getFileManager().getVirtualFileSystem());
        if (!FileStyle)
            FileStyle = format::getLLVMStyle();

        if (!SkipInsert) {
            tooling::HeaderIncludes HeaderIncludes(getCurrentMainFile(), Code,
                                                   FileStyle->IncludeStyle);
            // Deduplicate insertions when running in bulk fix mode.
            llvm::StringSet<> InsertedHeaders{};
            for (const auto&Inc: Missing) {
                std::string Spelling = include_cleaner::spellHeader(
                    {Inc.Missing, PP->getHeaderSearchInfo(), MainFile});
                bool Angled = llvm::StringRef{Spelling}.starts_with("<");
                // We might suggest insertion of an existing include in edge cases, e.g.,
                // include is present in a PP-disabled region, or spelling of the header
                // turns out to be the same as one of the unresolved includes in the
                // main file.
                if (auto Replacement =
                        HeaderIncludes.insert(llvm::StringRef{Spelling}.trim("\"<>"),
                                              Angled, tooling::IncludeDirective::Include)) {
                    DiagnosticBuilder DB =
                            diag(SM->getSpellingLoc(Inc.SymRef.RefLocation),
                                 "no header providing \"%0\" is directly included")
                            << Inc.SymRef.Target.name();
                    if (areDiagsSelfContained() ||
                        InsertedHeaders.insert(Replacement->getReplacementText()).second) {
                        DB << FixItHint::CreateInsertion(
                            SM->getComposedLoc(SM->getMainFileID(), Replacement->getOffset()),
                            Replacement->getReplacementText());
                    }
                }
            }
        }
        else {
            llvm::outs() << "Skipping include cleaner header insertion due to the SkipInsert\n";
        }

        if (!SkipRemove) {
            for (const auto* Inc: Unused) {
                diag(Inc->HashLocation, "included header %0 is not used directly")
                        << llvm::sys::path::filename(Inc->Spelled,
                                                     llvm::sys::path::Style::posix)
                        << FixItHint::CreateRemoval(CharSourceRange::getCharRange(
                            SM->translateLineCol(SM->getMainFileID(), Inc->Line, 1),
                            SM->translateLineCol(SM->getMainFileID(), Inc->Line + 1, 1)));
            }
        }
        else {
            llvm::outs()
                    << "Skipping include cleaner header removal due to the SkipRemove\n";
        }
    }
} // namespace clang::tidy::misc
