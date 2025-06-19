package com.quizlet.quizletandroid.ui.startpage.nav2.screenstates;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class x extends s {
    public final long a;
    public final Integer b;

    public x(long j, Integer num) {
        this.a = j;
        this.b = num;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof x)) {
            return false;
        }
        x xVar = (x) obj;
        return this.a == xVar.a && Intrinsics.b(this.b, xVar.b);
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        Integer num = this.b;
        return iHashCode + (num == null ? 0 : num.hashCode());
    }

    public final String toString() {
        return "ShowRecommendedSetActionOptions(setId=" + this.a + ", recsSectionNumber=" + this.b + ")";
    }
}
