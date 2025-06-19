package com.quizlet.features.practicetest.takingtest.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class A implements E {
    public final String a;
    public final String b;

    public A(String questionBankId, String str) {
        Intrinsics.checkNotNullParameter(questionBankId, "questionBankId");
        this.a = questionBankId;
        this.b = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof A)) {
            return false;
        }
        A a = (A) obj;
        return Intrinsics.b(this.a, a.a) && Intrinsics.b(this.b, a.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        String str = this.b;
        return iHashCode + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Details(questionBankId=");
        sb.append(this.a);
        sb.append(", practiceTestSessionId=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
