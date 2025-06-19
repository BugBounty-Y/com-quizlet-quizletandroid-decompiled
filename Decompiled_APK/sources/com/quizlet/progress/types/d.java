package com.quizlet.progress.types;

import androidx.compose.animation.d0;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public final List a;
    public final List b;
    public final Object c;

    public d(List notStudied, List stillLearning, List mastered) {
        Intrinsics.checkNotNullParameter(notStudied, "notStudied");
        Intrinsics.checkNotNullParameter(stillLearning, "stillLearning");
        Intrinsics.checkNotNullParameter(mastered, "mastered");
        this.a = notStudied;
        this.b = stillLearning;
        this.c = mastered;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return Intrinsics.b(this.a, dVar.a) && Intrinsics.b(this.b, dVar.b) && Intrinsics.b(this.c, dVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.f(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ProgressBuckets(notStudied=");
        sb.append(this.a);
        sb.append(", stillLearning=");
        sb.append(this.b);
        sb.append(", mastered=");
        return android.support.v4.media.session.a.s(sb, this.c, ")");
    }
}
