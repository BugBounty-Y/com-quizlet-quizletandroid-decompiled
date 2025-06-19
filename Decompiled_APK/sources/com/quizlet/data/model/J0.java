package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class J0 {
    public static final J0 e = new J0(0, 13);
    public final int a;
    public final int b;
    public final int c;
    public final String d;

    public /* synthetic */ J0(int i, int i2) {
        this(0, (i2 & 2) != 0 ? 0 : 1, null, (i2 & 4) != 0 ? 0 : i);
    }

    public static J0 a(J0 j0, int i, int i2, int i3) {
        int i4 = j0.a;
        if ((i3 & 2) != 0) {
            i = j0.b;
        }
        if ((i3 & 4) != 0) {
            i2 = j0.c;
        }
        String str = j0.d;
        j0.getClass();
        return new J0(i4, i, str, i2);
    }

    public final J0 b() {
        int i;
        int i2 = this.a;
        if (i2 <= 0 || (i = this.c) <= 0) {
            return null;
        }
        int i3 = this.b;
        if (i * i3 < i2) {
            return a(this, i3 + 1, 0, 13);
        }
        return null;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof J0)) {
            return false;
        }
        J0 j0 = (J0) obj;
        return this.a == j0.a && this.b == j0.b && this.c == j0.c && Intrinsics.b(this.d, j0.d);
    }

    public final int hashCode() {
        int iB = androidx.compose.animation.d0.b(this.c, androidx.compose.animation.d0.b(this.b, Integer.hashCode(this.a) * 31, 31), 31);
        String str = this.d;
        return iB + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PagingKey(total=");
        sb.append(this.a);
        sb.append(", page=");
        sb.append(this.b);
        sb.append(", perPage=");
        sb.append(this.c);
        sb.append(", pagingToken=");
        return android.support.v4.media.session.a.t(sb, this.d, ")");
    }

    public J0(int i, int i2, String str, int i3) {
        this.a = i;
        this.b = i2;
        this.c = i3;
        this.d = str;
    }
}
