package com.bumptech.glide.load;

import android.text.TextUtils;

/* loaded from: classes.dex */
public final class g {
    public static final retrofit2.adapter.rxjava3.d e = new retrofit2.adapter.rxjava3.d(5);
    public final Object a;
    public final f b;
    public final String c;
    public volatile byte[] d;

    public g(String str, Object obj, f fVar) {
        if (TextUtils.isEmpty(str)) {
            throw new IllegalArgumentException("Must not be null or empty");
        }
        this.c = str;
        this.a = obj;
        this.b = fVar;
    }

    public static g a(Object obj, String str) {
        return new g(str, obj, e);
    }

    public final boolean equals(Object obj) {
        if (obj instanceof g) {
            return this.c.equals(((g) obj).c);
        }
        return false;
    }

    public final int hashCode() {
        return this.c.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("Option{key='"), this.c, "'}");
    }
}
