package com.quizlet.features.practicetest.takingtest.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class D implements E {
    public final String a;

    public D(String practiceTestId) {
        Intrinsics.checkNotNullParameter(practiceTestId, "practiceTestId");
        this.a = practiceTestId;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof D) && Intrinsics.b(this.a, ((D) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("WebPage(practiceTestId="), this.a, ")");
    }
}
