package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class X0 {
    public final String a;
    public final long b;
    public final long c;

    public X0(long j, long j2, String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        this.a = name;
        this.b = j;
        this.c = j2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof X0)) {
            return false;
        }
        X0 x0 = (X0) obj;
        return Intrinsics.b(this.a, x0.a) && this.b == x0.b && this.c == x0.c;
    }

    public final int hashCode() {
        return Long.hashCode(this.c) + androidx.compose.animation.d0.d(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("UpdateFolderInfo(name=");
        sb.append(this.a);
        sb.append(", schoolId=");
        sb.append(this.b);
        sb.append(", courseId=");
        return android.support.v4.media.session.a.g(this.c, ")", sb);
    }
}
