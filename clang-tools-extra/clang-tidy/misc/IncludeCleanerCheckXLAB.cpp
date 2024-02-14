//===--- IncludeCleanerCheckXLAB.cpp - clang-tidy -----------------------------===//
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
#include <optional>
#include <string>
#include <vector>
#include <clang/AST/RecursiveASTVisitor.h>

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
          SkipRemove(
              Options.getLocalOrGlobal("SkipRemove", false)),
          SkipInsert(
              Options.getLocalOrGlobal("SkipInsert", false)),
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
        Finder->addMatcher(translationUnitDecl().bind("top"), this);
    }

    void IncludeCleanerCheckXLAB::registerPPCallbacks(const SourceManager&SM,
                                                      Preprocessor* PP,
                                                      Preprocessor* ModuleExpanderPP) {
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
        for (Decl* D: Result.Nodes.getNodeAs<TranslationUnitDecl>("top")->decls()) {
            if (!SM->isWrittenInMainFile(SM->getExpansionLoc(D->getLocation())))
                continue;
            // FIXME: Filter out implicit template specializations.
            MainFileDecls.push_back(D);
        }

        class MemberExprVisitor : public RecursiveASTVisitor<MemberExprVisitor> {
        public:
            explicit MemberExprVisitor(ASTContext* context, llvm::SmallVector<Decl *>&VEC)
                : MainFileDecls(VEC), Context(context), SM(Context->getSourceManager()) {
            }

            bool VisitMemberExpr(MemberExpr* ME) {
                if (!SM.isWrittenInMainFile(ME->getExprLoc())) {
                    return true;
                }
                // llvm::outs() << "Found MemberExpr: " << ME->getSourceRange().printToString(Context->getSourceManager()) << '\n';
                // Handle the current MemberExpr
                if (ValueDecl* VD = ME->getMemberDecl()) {
                    // llvm::outs() << "Found ValueDecl: " << VD->getSourceRange().printToString(Context->getSourceManager()) << '\n';
                    MainFileDecls.push_back(dyn_cast<Decl>(VD));
                }

                // Recursively visit the base of the MemberExpr
                // if (auto *Base = dyn_cast<MemberExpr>(ME->getBase())) {
                //     VisitMemberExpr(Base);
                // }

                return true;
            }

            clang::Decl* extractType(clang::CXXMemberCallExpr* callExpr) {
                llvm::outs() << "Found callExpr: " << callExpr->getSourceRange().printToString(Context->getSourceManager()) << '\n';
                if (!callExpr) return nullptr;
                //llvm::outs() << "HERE 1 \n";
                Expr *objectExpr = callExpr->getImplicitObjectArgument();
                if (objectExpr) {
                    //llvm::outs() << "HERE 2 \n";
                    objectExpr = objectExpr->IgnoreParenImpCasts(); // Clean up the expression
                    //objectExpr->dump(llvm::outs(), *Context);
                    llvm::outs() << "Found objectExpr: " << objectExpr->getSourceRange().printToString(Context->getSourceManager()) << '\n';
                    if (DeclRefExpr *declRef = dyn_cast<DeclRefExpr>(objectExpr)) {
                        // If the object expression is a reference to a declaration, get that declaration
                        ValueDecl *objectDecl = declRef->getDecl();
                        llvm::outs() << "Found objectDecl: " << objectDecl->getSourceRange().printToString(Context->getSourceManager()) << '\n';
                        return objectDecl;
                        // Now objectDecl points to the declaration of the object
                    } else if (MemberExpr *memberExpr = dyn_cast<MemberExpr>(objectExpr)) {
                        // If the object expression is a member of another object, get that member's declaration
                        ValueDecl *memberDecl = memberExpr->getMemberDecl();
                        llvm::outs() << "Found member decl: " << memberDecl->getSourceRange().printToString(Context->getSourceManager()) << '\n';
                        return memberDecl;
                        // memberDecl now points to the declaration of the member
                    } else if (CallExpr* callExpr = dyn_cast<CallExpr>(objectExpr)) {
                        // If the object expression is a member of another object, get that member's declaration
                        auto *decl = callExpr->getCalleeDecl();
                        auto *callee = callExpr->getCallee();
                        llvm::outs() << "Found call decl: " << decl->getSourceRange().printToString(Context->getSourceManager()) << '\n';
                        return decl;
                    }
                    // Additional cases can be handled similarly depending on the types of expressions you expect
                }

                return nullptr;
            }

            bool VisitCXXMemberCallExpr(CXXMemberCallExpr* MCE) {
                if (!SM.isWrittenInMainFile(MCE->getExprLoc())) {
                    return true;
                }
                if (auto* Decl = extractType(MCE)) {
                    MainFileDecls.push_back(Decl);
                }

                return true;
            }

        private:
            llvm::SmallVector<Decl *>&MainFileDecls;
            ASTContext* Context;
            SourceManager&SM;
        };
        MemberExprVisitor visitor(Result.Context, MainFileDecls);
        visitor.TraverseDecl(Result.Context->getTranslationUnitDecl());
        // llvm::outs() << "Result: " << res << '\n';

        llvm::DenseSet<include_cleaner::Symbol> SeenSymbols;
        OptionalDirectoryEntryRef ResourceDir =
                PP->getHeaderSearchInfo().getModuleMap().getBuiltinDir();

        // llvm::outs() << "Found declarations: \n";
        // for(const auto d : MainFileDecls) {
        //     llvm::outs() << d->getLocation().printToString(Result.Context->getSourceManager()) << '\n';
        // }

        // FIXME: Find a way to have less code duplication between include-cleaner
        // analysis implementation and the below code.
        walkUsed(MainFileDecls, RecordedPreprocessor.MacroReferences, &RecordedPI,
                 *PP,
                 [&](const include_cleaner::SymbolReference&Ref,
                     llvm::ArrayRef<include_cleaner::Header> Providers) {
                     // llvm::outs() << Ref.RefLocation.printToString(Result.Context->getSourceManager()) << '\n';


                     // Process each symbol once to reduce noise in the findings.
                     // Tidy checks are used in two different workflows:
                     // - Ones that show all the findings for a given file. For such
                     // workflows there is not much point in showing all the occurences,
                     // as one is enough to indicate the issue.
                     // - Ones that show only the findings on changed pieces. For such
                     // workflows it's useful to show findings on every reference of a
                     // symbol as otherwise tools might give incosistent results
                     // depending on the parts of the file being edited. But it should
                     // still help surface findings for "new violations" (i.e.
                     // dependency did not exist in the code at all before).
                     if (DeduplicateFindings && !SeenSymbols.insert(Ref.Target).second)
                         return;
                     // llvm::outs() << "Continue...\n";
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
                     // auto rt = Ref.RT == include_cleaner::RefType::Explicit ? "Explicit" : (Ref.RT == include_cleaner::RefType::Implicit ? "Implicit" : "Ambiguous");
                     // llvm::outs() << "Satisfied " << Satisfied << " !Providers.empty() " << Providers.empty() << " RefType " << rt << '\n';

                     if (!Satisfied && !Providers.empty() &&
                         Ref.RT != include_cleaner::RefType::Ambiguous &&
                         !shouldIgnore(Providers.front()) &&
                         shouldInclude(Providers.front())) {
                         // llvm::outs() << "MISSING!\n";
                         Missing.push_back({Ref, Providers.front()});
                     }
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
            llvm::outs() << "Skipping include cleaner header removal due to the SkipRemove\n";
        }

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
    }
} // namespace clang::tidy::misc
