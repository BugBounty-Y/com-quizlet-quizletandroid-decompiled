package com.quizlet.quizletandroid.ui.library.data;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.library.data.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4647a {
    public final long a;
    public final String b;
    public final int c;

    public C4647a(int i, long j, String className) {
        Intrinsics.checkNotNullParameter(className, "className");
        this.a = j;
        this.b = className;
        this.c = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4647a)) {
            return false;
        }
        C4647a c4647a = (C4647a) obj;
        return this.a == c4647a.a && Intrinsics.b(this.b, c4647a.b) && this.c == c4647a.c;
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + d0.e(Long.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ClassData(classId=");
        sb.append(this.a);
        sb.append(", className=");
        sb.append(this.b);
        sb.append(", sets=");
        return android.support.v4.media.session.a.r(sb, this.c, ")");
    }
}
