package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class C {
    public final long a;
    public final String b;
    public final int c;

    public C(int i, long j, String className) {
        Intrinsics.checkNotNullParameter(className, "className");
        this.a = j;
        this.b = className;
        this.c = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C)) {
            return false;
        }
        C c = (C) obj;
        return this.a == c.a && Intrinsics.b(this.b, c.b) && this.c == c.c;
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + androidx.compose.animation.d0.e(Long.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ClassCard(classId=");
        sb.append(this.a);
        sb.append(", className=");
        sb.append(this.b);
        sb.append(", numOfSets=");
        return android.support.v4.media.session.a.r(sb, this.c, ")");
    }
}
