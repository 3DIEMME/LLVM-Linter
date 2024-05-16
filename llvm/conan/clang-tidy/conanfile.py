import os
from conan import ConanFile
from conan.tools.files import copy
from conans.errors import ConanInvalidConfiguration


class ClangTidyPackage(ConanFile):
    name = "clang-tidy"
    settings = "os"

    def validate(self):
        if self.settings.os != "Windows":
            raise ConanInvalidConfiguration("Only Windows is supported")

    def export_sources(self):
        copy(self, "clang-tidy.exe", self.recipe_folder, self.export_sources_folder)

    def package(self):
        copy(self, "clang-tidy.exe", self.export_sources_folder, os.path.join(self.package_folder, "bin"))