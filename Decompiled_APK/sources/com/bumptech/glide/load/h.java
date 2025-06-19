package com.bumptech.glide.load;

import java.security.MessageDigest;

/* loaded from: classes.dex */
public final class h implements e {
    public final com.bumptech.glide.util.c b = new com.bumptech.glide.util.c(0);

    @Override // com.bumptech.glide.load.e
    public final void a(MessageDigest messageDigest) {
        int i = 0;
        while (true) {
            com.bumptech.glide.util.c cVar = this.b;
            if (i >= cVar.c) {
                return;
            }
            g gVar = (g) cVar.g(i);
            Object objK = this.b.k(i);
            f fVar = gVar.b;
            if (gVar.d == null) {
                gVar.d = gVar.c.getBytes(e.a);
            }
            fVar.a(gVar.d, objK, messageDigest);
            i++;
        }
    }

    public final Object c(g gVar) {
        com.bumptech.glide.util.c cVar = this.b;
        return cVar.containsKey(gVar) ? cVar.get(gVar) : gVar.a;
    }

    @Override // com.bumptech.glide.load.e
    public final boolean equals(Object obj) {
        if (obj instanceof h) {
            return this.b.equals(((h) obj).b);
        }
        return false;
    }

    @Override // com.bumptech.glide.load.e
    public final int hashCode() {
        return this.b.hashCode();
    }

    public final String toString() {
        return "Options{values=" + this.b + '}';
    }
}
