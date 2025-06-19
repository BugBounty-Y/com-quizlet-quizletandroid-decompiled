package com.quizlet.remote.model.universaluploadflow;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class UniversalUploadFlowPracticeTestsStatusResponse extends ApiResponse {
    public final UniversalUploadFlowPracticeTestsStatusModels d;

    public UniversalUploadFlowPracticeTestsStatusResponse(UniversalUploadFlowPracticeTestsStatusModels models) {
        Intrinsics.checkNotNullParameter(models, "models");
        this.d = models;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof UniversalUploadFlowPracticeTestsStatusResponse) && Intrinsics.b(this.d, ((UniversalUploadFlowPracticeTestsStatusResponse) obj).d);
    }

    public final int hashCode() {
        return this.d.a.hashCode();
    }

    public final String toString() {
        return "UniversalUploadFlowPracticeTestsStatusResponse(models=" + this.d + ")";
    }
}
