package com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.n, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4745n extends M {
    public final long a;
    public final Integer b;

    public C4745n(long j, Integer num) {
        this.a = j;
        this.b = num;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4745n)) {
            return false;
        }
        C4745n c4745n = (C4745n) obj;
        return this.a == c4745n.a && Intrinsics.b(this.b, c4745n.b);
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        Integer num = this.b;
        return iHashCode + (num == null ? 0 : num.hashCode());
    }

    public final String toString() {
        return "GoToHideRecommendationFeedback(setId=" + this.a + ", recsSectionNumber=" + this.b + ")";
    }
}
