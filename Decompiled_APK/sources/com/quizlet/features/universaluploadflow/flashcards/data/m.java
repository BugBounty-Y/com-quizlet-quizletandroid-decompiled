package com.quizlet.features.universaluploadflow.flashcards.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m implements o {
    public final String a;

    public m(String questionBankId) {
        Intrinsics.checkNotNullParameter(questionBankId, "questionBankId");
        this.a = questionBankId;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof m) && Intrinsics.b(this.a, ((m) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("PracticeTests(questionBankId="), this.a, ")");
    }
}
