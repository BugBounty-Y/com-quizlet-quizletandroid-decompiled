package com.google.android.gms.internal.ads;

import android.net.Uri;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/* loaded from: classes2.dex */
public final class V1 {
    public final Uri a;
    public final List b;
    public final Bu c;

    static {
        String str = Yo.a;
        Integer.toString(0, 36);
        Integer.toString(1, 36);
        Integer.toString(2, 36);
        Integer.toString(3, 36);
        Integer.toString(4, 36);
        Integer.toString(5, 36);
        Integer.toString(6, 36);
        Integer.toString(7, 36);
    }

    public V1(Uri uri, Bu bu) {
        List list = Collections.EMPTY_LIST;
        this.a = uri;
        ArrayList arrayList = AbstractC2514q5.a;
        this.b = list;
        this.c = bu;
        C2244ju c2244ju = AbstractC2330lu.b;
        AbstractC2543qs.g(4, "initialCapacity");
        Object[] objArr = new Object[4];
        if (bu.d <= 0) {
            AbstractC2330lu.m(0, objArr);
        } else {
            bu.get(0);
            throw new ClassCastException();
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof V1)) {
            return false;
        }
        V1 v1 = (V1) obj;
        return this.a.equals(v1.a) && this.b.equals(v1.b) && this.c.equals(v1.c);
    }

    public final int hashCode() {
        return (int) ((((this.c.hashCode() + androidx.compose.animation.d0.f(this.a.hashCode() * 923521, 961, this.b)) * 31) * 31) - Long.MAX_VALUE);
    }
}
