# $FreeBSD$

.PATH: ${.CURDIR:H:H}/fs/tarfs

KMOD=	tarfs
SRCS=	vnode_if.h \
	tarfs_subr.c \
	tarfs_vnops.c \
	tarfs_vfsops.c

.ifdef TARFS_DEBUG
CFLAGS+=	-DTARFS_DEBUG
.endif

.include <bsd.kmod.mk>

