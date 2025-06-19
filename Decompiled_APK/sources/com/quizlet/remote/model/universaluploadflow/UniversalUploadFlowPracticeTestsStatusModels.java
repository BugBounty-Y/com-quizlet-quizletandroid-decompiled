package com.quizlet.remote.model.universaluploadflow;

import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class UniversalUploadFlowPracticeTestsStatusModels {
    public final List a;

    public UniversalUploadFlowPracticeTestsStatusModels(List questionBankStatus) {
        Intrinsics.checkNotNullParameter(questionBankStatus, "questionBankStatus");
        this.a = questionBankStatus;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof UniversalUploadFlowPracticeTestsStatusModels) && Intrinsics.b(this.a, ((UniversalUploadFlowPracticeTestsStatusModels) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("UniversalUploadFlowPracticeTestsStatusModels(questionBankStatus="), this.a);
    }
}
