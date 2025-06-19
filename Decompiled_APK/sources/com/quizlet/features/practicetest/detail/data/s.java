package com.quizlet.features.practicetest.detail.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class s implements D {
    public final String a;

    public s(String redirectQuestionBankUuid) {
        Intrinsics.checkNotNullParameter(redirectQuestionBankUuid, "redirectQuestionBankUuid");
        this.a = redirectQuestionBankUuid;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof s) && Intrinsics.b(this.a, ((s) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("Login(redirectQuestionBankUuid="), this.a, ")");
    }
}
