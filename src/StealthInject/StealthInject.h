/*  This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>. */

#ifndef STEALTH_INJECT_H
#define STEALTH_INJECT_H

void StealthLoadLibrary(void* hProcess, const char* path);
bool StealthLoadLibraryMemory(void* hProcess, void* address);

#endif //STEALTH_INJECT_H
