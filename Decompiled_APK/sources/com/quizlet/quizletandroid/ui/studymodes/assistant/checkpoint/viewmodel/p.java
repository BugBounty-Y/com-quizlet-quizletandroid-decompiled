package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel;

import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class p {
    public final List a;
    public final List b;

    public p(List neverCorrect, List correctOnce) {
        Intrinsics.checkNotNullParameter(neverCorrect, "neverCorrect");
        Intrinsics.checkNotNullParameter(correctOnce, "correctOnce");
        this.a = neverCorrect;
        this.b = correctOnce;
    }

    public final List a(o bucket) {
        Intrinsics.checkNotNullParameter(bucket, "bucket");
        int iOrdinal = bucket.ordinal();
        if (iOrdinal == 0) {
            return this.a;
        }
        if (iOrdinal == 1) {
            return this.b;
        }
        throw new NoWhenBranchMatchedException();
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof p)) {
            return false;
        }
        p pVar = (p) obj;
        return Intrinsics.b(this.a, pVar.a) && Intrinsics.b(this.b, pVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "WriteTermBuckets(neverCorrect=" + this.a + ", correctOnce=" + this.b + ")";
    }
}
