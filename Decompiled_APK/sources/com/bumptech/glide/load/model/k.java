package com.bumptech.glide.load.model;

/* loaded from: classes.dex */
public final class k {
    public final String a;

    public k(String str) {
        this.a = str;
    }

    public final boolean equals(Object obj) {
        if (obj instanceof k) {
            return this.a.equals(((k) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("StringHeaderFactory{value='"), this.a, "'}");
    }
}
