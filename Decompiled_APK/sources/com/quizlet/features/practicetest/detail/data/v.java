package com.quizlet.features.practicetest.detail.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class v implements D {
    public final String a;

    public v(String questionBankUuid) {
        Intrinsics.checkNotNullParameter(questionBankUuid, "questionBankUuid");
        this.a = questionBankUuid;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof v) && Intrinsics.b(this.a, ((v) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("PracticeTestWeb(questionBankUuid="), this.a, ")");
    }
}
