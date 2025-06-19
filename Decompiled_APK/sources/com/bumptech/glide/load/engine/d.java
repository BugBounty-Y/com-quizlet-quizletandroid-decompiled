package com.bumptech.glide.load.engine;

import java.security.MessageDigest;

/* loaded from: classes.dex */
public final class d implements com.bumptech.glide.load.e {
    public final com.bumptech.glide.load.e b;
    public final com.bumptech.glide.load.e c;

    public d(com.bumptech.glide.load.e eVar, com.bumptech.glide.load.e eVar2) {
        this.b = eVar;
        this.c = eVar2;
    }

    @Override // com.bumptech.glide.load.e
    public final void a(MessageDigest messageDigest) {
        this.b.a(messageDigest);
        this.c.a(messageDigest);
    }

    @Override // com.bumptech.glide.load.e
    public final boolean equals(Object obj) {
        if (obj instanceof d) {
            d dVar = (d) obj;
            if (this.b.equals(dVar.b) && this.c.equals(dVar.c)) {
                return true;
            }
        }
        return false;
    }

    @Override // com.bumptech.glide.load.e
    public final int hashCode() {
        return this.c.hashCode() + (this.b.hashCode() * 31);
    }

    public final String toString() {
        return "DataCacheKey{sourceKey=" + this.b + ", signature=" + this.c + '}';
    }
}
