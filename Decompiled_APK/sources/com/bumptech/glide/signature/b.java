package com.bumptech.glide.signature;

import com.bumptech.glide.load.e;
import com.bumptech.glide.util.f;
import java.security.MessageDigest;

/* loaded from: classes.dex */
public final class b implements e {
    public final Object b;

    public b(Object obj) {
        f.c(obj, "Argument must not be null");
        this.b = obj;
    }

    @Override // com.bumptech.glide.load.e
    public final void a(MessageDigest messageDigest) {
        messageDigest.update(this.b.toString().getBytes(e.a));
    }

    @Override // com.bumptech.glide.load.e
    public final boolean equals(Object obj) {
        if (obj instanceof b) {
            return this.b.equals(((b) obj).b);
        }
        return false;
    }

    @Override // com.bumptech.glide.load.e
    public final int hashCode() {
        return this.b.hashCode();
    }

    public final String toString() {
        return "ObjectKey{object=" + this.b + '}';
    }
}
