package com.quizlet.features.universaluploadflow.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class B implements F {
    public final String a;

    public B(String questionBankId) {
        Intrinsics.checkNotNullParameter(questionBankId, "questionBankId");
        this.a = questionBankId;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof B) && Intrinsics.b(this.a, ((B) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("PracticeTests(questionBankId="), this.a, ")");
    }
}
