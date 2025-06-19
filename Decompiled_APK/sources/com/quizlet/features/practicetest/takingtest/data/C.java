package com.quizlet.features.practicetest.takingtest.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class C implements E {
    public final String a;
    public final String b;

    public C(String practiceTestId, String practiceTestSessionId) {
        Intrinsics.checkNotNullParameter(practiceTestId, "practiceTestId");
        Intrinsics.checkNotNullParameter(practiceTestSessionId, "practiceTestSessionId");
        this.a = practiceTestId;
        this.b = practiceTestSessionId;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C)) {
            return false;
        }
        C c = (C) obj;
        return Intrinsics.b(this.a, c.a) && Intrinsics.b(this.b, c.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Results(practiceTestId=");
        sb.append(this.a);
        sb.append(", practiceTestSessionId=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
