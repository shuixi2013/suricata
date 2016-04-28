/* Copyright (C) 2016 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <gelf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "suricata.h"
#include "util-ebpf.h"

#define LB_FUNC_NAME "loadbalancer"

static int openelf(const char *path, Elf **elf_out, int *fd_out) {
    if (elf_version(EV_CURRENT) == EV_NONE)
        return -1;

    *fd_out = open(path, O_RDONLY);
    if (*fd_out < 0)
        return -1;

    *elf_out = elf_begin(*fd_out, ELF_C_READ, 0);
    if (*elf_out == 0) {
        close(*fd_out);
        return -1;
    }

    return 0;
}


/* TODO
 * Assume we have only one section
 * Build list of offset ordered list symbols in the section
 * Once done, we can build a list of function with start and end of each one
 */

static MemBuffer *list_in_scn(Elf *e, Elf_Scn *section, size_t stridx, size_t symsize)
{
    Elf_Data *data = NULL;

    while ((data = elf_getdata(section, data)) != 0) {
        size_t i, symcount = data->d_size / symsize;

        if (data->d_size % symsize)
            return NULL;

        for (i = 0; i < symcount; ++i) {
            GElf_Sym sym;
            const char *name;

            if (!gelf_getsym(data, (int)i, &sym))
                continue;

            if ((name = elf_strptr(e, stridx, sym.st_name)) == NULL)
                continue;

//            printf("Name is '%s', index: %d, value: %d, size: %d\n", name, sym.st_shndx, sym.st_value, sym.st_size);
            if (!strcmp(LB_FUNC_NAME, name)) {
                MemBuffer *buf = NULL;
                Elf_Scn *dsection = elf_getscn(e, sym.st_shndx);
                Elf_Data *ddata = NULL;
                ddata = elf_getdata(dsection, ddata);
                if (ddata == NULL) {
                    /* FIXME Error  msg */
                    return NULL;
                }
                /* FIXME  sanity check on subs */
                int buflen = ddata->d_size - sym.st_value;
                buf = MemBufferCreateNew(buflen);
                if (buf == NULL) {
                    /* FIXME Error  msg */
                    return NULL;
                }
                MemBufferWriteRaw(buf, ((uint8_t *)ddata->d_buf) + sym.st_value, (ddata->d_size - sym.st_value));
                return buf;
            }
        }
    }

    return NULL;
}


static MemBuffer * listsymbols(Elf *e) {
  Elf_Scn *section = NULL;
  MemBuffer *buf;

  while ((section = elf_nextscn(e, section)) != 0) {
    GElf_Shdr header;

    if (!gelf_getshdr(section, &header))
      continue;

    if (header.sh_type != SHT_SYMTAB && header.sh_type != SHT_DYNSYM)
      continue;

    buf = list_in_scn(e, section, header.sh_link, header.sh_entsize);

    return buf;
  }

  return NULL;
}


MemBuffer *ebpf_get_lb_func(const char *filename)
{
    Elf *e;
    MemBuffer *ebpf_buf;
    int fd;

    if (openelf(filename, &e, &fd) < 0) {
        return NULL;
    }

    ebpf_buf = listsymbols(e);
    elf_end(e);
    close(fd);
    return ebpf_buf;
}
