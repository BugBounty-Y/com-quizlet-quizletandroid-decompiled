package com.quizlet.features.setpage.progress;

import androidx.compose.animation.d0;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final List a;
    public final List b;
    public final Object c;

    public b(List notStudied, List stillLearning, List mastered) {
        Intrinsics.checkNotNullParameter(notStudied, "notStudied");
        Intrinsics.checkNotNullParameter(stillLearning, "stillLearning");
        Intrinsics.checkNotNullParameter(mastered, "mastered");
        this.a = notStudied;
        this.b = stillLearning;
        this.c = mastered;
    }

    /* JADX WARN: Type inference failed for: r2v5, types: [java.lang.Object, java.util.List] */
    public final List a(a bucket) {
        Intrinsics.checkNotNullParameter(bucket, "bucket");
        int iOrdinal = bucket.ordinal();
        if (iOrdinal == 0) {
            return this.a;
        }
        if (iOrdinal == 1) {
            return this.b;
        }
        if (iOrdinal == 2) {
            return this.c;
        }
        throw new NoWhenBranchMatchedException();
    }

    /* JADX WARN: Type inference failed for: r0v2, types: [java.lang.Object, java.util.List] */
    public final int b() {
        return this.c.size() + this.b.size() + this.a.size();
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && Intrinsics.b(this.b, bVar.b) && Intrinsics.b(this.c, bVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.f(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ProgressData(notStudied=");
        sb.append(this.a);
        sb.append(", stillLearning=");
        sb.append(this.b);
        sb.append(", mastered=");
        return android.support.v4.media.session.a.s(sb, this.c, ")");
    }
}
