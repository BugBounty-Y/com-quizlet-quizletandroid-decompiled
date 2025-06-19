package com.quizlet.remote.model.practicetests;

import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteQuestionBankUuid {
    public final String a;

    public RemoteQuestionBankUuid(String questionBankUuid) {
        Intrinsics.checkNotNullParameter(questionBankUuid, "questionBankUuid");
        this.a = questionBankUuid;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RemoteQuestionBankUuid) && Intrinsics.b(this.a, ((RemoteQuestionBankUuid) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("RemoteQuestionBankUuid(questionBankUuid="), this.a, ")");
    }
}
