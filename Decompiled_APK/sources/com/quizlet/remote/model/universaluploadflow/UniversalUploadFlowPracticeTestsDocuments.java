package com.quizlet.remote.model.universaluploadflow;

import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class UniversalUploadFlowPracticeTestsDocuments {
    public final String a;

    public UniversalUploadFlowPracticeTestsDocuments(String questionBankId) {
        Intrinsics.checkNotNullParameter(questionBankId, "questionBankId");
        this.a = questionBankId;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof UniversalUploadFlowPracticeTestsDocuments) && Intrinsics.b(this.a, ((UniversalUploadFlowPracticeTestsDocuments) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("UniversalUploadFlowPracticeTestsDocuments(questionBankId="), this.a, ")");
    }
}
