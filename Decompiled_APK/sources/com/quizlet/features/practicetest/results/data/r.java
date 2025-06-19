package com.quizlet.features.practicetest.results.data;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class r implements s {
    public final String a;
    public final String b;
    public final String c;

    public r(String practiceTestId, String questionBankId, String str) {
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
        if (!(obj instanceof r)) {
            return false;
        }
        r rVar = (r) obj;
        return Intrinsics.b(this.a, rVar.a) && Intrinsics.b(this.b, rVar.b) && Intrinsics.b(this.c, rVar.c);
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
