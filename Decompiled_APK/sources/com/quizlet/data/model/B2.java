package com.quizlet.data.model;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class B2 {
    public final long a;
    public final String b;
    public final int c;
    public final int d;
    public final int e;
    public final int f;
    public final Object g;

    public B2(long j, String title, int i, int i2, int i3, int i4, List memoryScores) {
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(memoryScores, "memoryScores");
        this.a = j;
        this.b = title;
        this.c = i;
        this.d = i2;
        this.e = i3;
        this.f = i4;
        this.g = memoryScores;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof B2)) {
            return false;
        }
        B2 b2 = (B2) obj;
        return this.a == b2.a && this.b.equals(b2.b) && this.c == b2.c && this.d == b2.d && this.e == b2.e && this.f == b2.f && Intrinsics.b(this.g, b2.g);
    }

    public final int hashCode() {
        return this.g.hashCode() + androidx.compose.animation.d0.b(this.f, androidx.compose.animation.d0.b(this.e, androidx.compose.animation.d0.b(this.d, androidx.compose.animation.d0.b(this.c, androidx.compose.animation.d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31), 31), 31), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SetData(id=");
        sb.append(this.a);
        sb.append(", title=");
        sb.append(this.b);
        sb.append(", count=");
        sb.append(this.c);
        sb.append(", itemsKnown=");
        sb.append(this.d);
        sb.append(", itemsStillLearning=");
        sb.append(this.e);
        sb.append(", itemsRemaining=");
        sb.append(this.f);
        sb.append(", memoryScores=");
        return android.support.v4.media.session.a.s(sb, this.g, ")");
    }
}
