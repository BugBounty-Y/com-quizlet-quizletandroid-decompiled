package com.quizlet.features.practicetest.detail.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class z implements D {
    public final String a;

    public z(String redirectQuestionBankUuid) {
        Intrinsics.checkNotNullParameter(redirectQuestionBankUuid, "redirectQuestionBankUuid");
        this.a = redirectQuestionBankUuid;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof z) && Intrinsics.b(this.a, ((z) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("SignUp(redirectQuestionBankUuid="), this.a, ")");
    }
}
