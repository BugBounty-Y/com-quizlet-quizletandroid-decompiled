package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class A1 {
    public final int a;
    public final int b;
    public final String c;

    public A1(int i, int i2, String str) {
        this.a = i;
        this.b = i2;
        this.c = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof A1)) {
            return false;
        }
        A1 a1 = (A1) obj;
        return this.a == a1.a && this.b == a1.b && Intrinsics.b(this.c, a1.c);
    }

    public final int hashCode() {
        int iB = androidx.compose.animation.d0.b(this.b, Integer.hashCode(this.a) * 31, 31);
        String str = this.c;
        return iB + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SearchPagingKey(total=");
        sb.append(this.a);
        sb.append(", page=");
        sb.append(this.b);
        sb.append(", pagingToken=");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }
}
