package com.quizlet.features.practicetest.detail.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class y implements D {
    public final com.quizlet.features.infra.models.share.a a;

    public y(com.quizlet.features.infra.models.share.a data) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.a = data;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof y) && Intrinsics.b(this.a, ((y) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Share(data=" + this.a + ")";
    }
}
