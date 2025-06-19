package com.quizlet.features.infra.basestudy.data.models;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m implements w {
    public final com.quizlet.inapp.model.a a;

    public m(com.quizlet.inapp.model.a reviewInfo) {
        Intrinsics.checkNotNullParameter(reviewInfo, "reviewInfo");
        this.a = reviewInfo;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof m) && Intrinsics.b(this.a, ((m) obj).a);
    }

    public final int hashCode() {
        return this.a.a.hashCode();
    }

    public final String toString() {
        return "ShowAppReview(reviewInfo=" + this.a + ")";
    }
}
