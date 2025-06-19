package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class F0 {
    public final long a;
    public final String b;
    public final String c;

    public F0(long j, String name, String str) {
        Intrinsics.checkNotNullParameter(name, "name");
        this.a = j;
        this.b = name;
        this.c = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof F0)) {
            return false;
        }
        F0 f0 = (F0) obj;
        return this.a == f0.a && Intrinsics.b(this.b, f0.b) && Intrinsics.b(this.c, f0.c);
    }

    public final int hashCode() {
        int iE = androidx.compose.animation.d0.e(Long.hashCode(this.a) * 31, 31, this.b);
        String str = this.c;
        return iE + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("NewFolder(creatorId=");
        sb.append(this.a);
        sb.append(", name=");
        sb.append(this.b);
        sb.append(", description=");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }
}
