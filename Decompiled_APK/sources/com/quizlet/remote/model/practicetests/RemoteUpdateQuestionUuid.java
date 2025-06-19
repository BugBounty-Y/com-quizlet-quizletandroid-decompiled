package com.quizlet.remote.model.practicetests;

import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteUpdateQuestionUuid {
    public final String a;

    public RemoteUpdateQuestionUuid(String questionUuid) {
        Intrinsics.checkNotNullParameter(questionUuid, "questionUuid");
        this.a = questionUuid;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RemoteUpdateQuestionUuid) && Intrinsics.b(this.a, ((RemoteUpdateQuestionUuid) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("RemoteUpdateQuestionUuid(questionUuid="), this.a, ")");
    }
}
