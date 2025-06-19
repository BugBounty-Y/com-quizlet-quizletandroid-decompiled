package com.quizlet.features.practicetest.detail.data;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class A implements D {
    public final String a;
    public final String b;
    public final String c;

    public A(String practiceTestId, String questionBankId, String str) {
        Intrinsics.checkNotNullParameter(practiceTestId, "practiceTestId");
        Intrinsics.checkNotNullParameter(questionBankId, "questionBankId");
        this.a = practiceTestId;
        this.b = questionBankId;
        this.c = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof A)) {
            return false;
        }
        A a = (A) obj;
        return Intrinsics.b(this.a, a.a) && Intrinsics.b(this.b, a.b) && Intrinsics.b(this.c, a.c);
    }

    public final int hashCode() {
        int iE = d0.e(this.a.hashCode() * 31, 31, this.b);
        String str = this.c;
        return iE + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TakeTest(practiceTestId=");
        sb.append(this.a);
        sb.append(", questionBankId=");
        sb.append(this.b);
        sb.append(", practiceTestSessionId=");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }
}
