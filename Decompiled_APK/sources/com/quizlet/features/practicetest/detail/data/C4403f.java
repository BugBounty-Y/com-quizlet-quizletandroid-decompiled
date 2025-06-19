package com.quizlet.features.practicetest.detail.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.practicetest.detail.data.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4403f implements p {
    public final String a;

    public C4403f(String practiceTestId) {
        Intrinsics.checkNotNullParameter(practiceTestId, "practiceTestId");
        this.a = practiceTestId;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4403f) && Intrinsics.b(this.a, ((C4403f) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("PastExamClicked(practiceTestId="), this.a, ")");
    }
}
