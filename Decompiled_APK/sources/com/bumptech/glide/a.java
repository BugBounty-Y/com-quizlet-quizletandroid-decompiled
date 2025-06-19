package com.bumptech.glide;

/* loaded from: classes.dex */
public final class a implements Cloneable {
    public com.bumptech.glide.request.transition.a a;

    /* renamed from: b, reason: merged with bridge method [inline-methods] */
    public final a clone() {
        try {
            return (a) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException(e);
        }
    }

    public final boolean c(Object obj) {
        if (obj instanceof a) {
            return com.bumptech.glide.util.m.b(this.a, ((a) obj).a);
        }
        return false;
    }

    public final int d() {
        com.bumptech.glide.request.transition.a aVar = this.a;
        if (aVar != null) {
            return aVar.hashCode();
        }
        return 0;
    }

    public final boolean equals(Object obj) {
        return (obj instanceof a) && c(obj);
    }

    public final int hashCode() {
        return d();
    }
}
