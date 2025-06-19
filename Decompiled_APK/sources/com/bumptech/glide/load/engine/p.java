package com.bumptech.glide.load.engine;

import java.security.MessageDigest;

/* loaded from: classes.dex */
public final class p implements com.bumptech.glide.load.e {
    public final Object b;
    public final int c;
    public final int d;
    public final Class e;
    public final Class f;
    public final com.bumptech.glide.load.e g;
    public final com.bumptech.glide.util.c h;
    public final com.bumptech.glide.load.h i;
    public int j;

    public p(Object obj, com.bumptech.glide.load.e eVar, int i, int i2, com.bumptech.glide.util.c cVar, Class cls, Class cls2, com.bumptech.glide.load.h hVar) {
        com.bumptech.glide.util.f.c(obj, "Argument must not be null");
        this.b = obj;
        this.g = eVar;
        this.c = i;
        this.d = i2;
        com.bumptech.glide.util.f.c(cVar, "Argument must not be null");
        this.h = cVar;
        com.bumptech.glide.util.f.c(cls, "Resource class must not be null");
        this.e = cls;
        com.bumptech.glide.util.f.c(cls2, "Transcode class must not be null");
        this.f = cls2;
        com.bumptech.glide.util.f.c(hVar, "Argument must not be null");
        this.i = hVar;
    }

    @Override // com.bumptech.glide.load.e
    public final void a(MessageDigest messageDigest) {
        throw new UnsupportedOperationException();
    }

    @Override // com.bumptech.glide.load.e
    public final boolean equals(Object obj) {
        if (!(obj instanceof p)) {
            return false;
        }
        p pVar = (p) obj;
        return this.b.equals(pVar.b) && this.g.equals(pVar.g) && this.d == pVar.d && this.c == pVar.c && this.h.equals(pVar.h) && this.e.equals(pVar.e) && this.f.equals(pVar.f) && this.i.equals(pVar.i);
    }

    @Override // com.bumptech.glide.load.e
    public final int hashCode() {
        if (this.j == 0) {
            int iHashCode = this.b.hashCode();
            this.j = iHashCode;
            int iHashCode2 = ((((this.g.hashCode() + (iHashCode * 31)) * 31) + this.c) * 31) + this.d;
            this.j = iHashCode2;
            int iHashCode3 = this.h.hashCode() + (iHashCode2 * 31);
            this.j = iHashCode3;
            int iHashCode4 = this.e.hashCode() + (iHashCode3 * 31);
            this.j = iHashCode4;
            int iHashCode5 = this.f.hashCode() + (iHashCode4 * 31);
            this.j = iHashCode5;
            this.j = this.i.b.hashCode() + (iHashCode5 * 31);
        }
        return this.j;
    }

    public final String toString() {
        return "EngineKey{model=" + this.b + ", width=" + this.c + ", height=" + this.d + ", resourceClass=" + this.e + ", transcodeClass=" + this.f + ", signature=" + this.g + ", hashCode=" + this.j + ", transformations=" + this.h + ", options=" + this.i + '}';
    }
}
