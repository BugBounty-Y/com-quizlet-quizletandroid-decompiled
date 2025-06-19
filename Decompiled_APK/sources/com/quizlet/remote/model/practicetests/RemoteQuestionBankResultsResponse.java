package com.quizlet.remote.model.practicetests;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteQuestionBankResultsResponse extends ApiResponse {
    public final QuestionBankResultResponse d;

    public RemoteQuestionBankResultsResponse(QuestionBankResultResponse models) {
        Intrinsics.checkNotNullParameter(models, "models");
        this.d = models;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RemoteQuestionBankResultsResponse) && Intrinsics.b(this.d, ((RemoteQuestionBankResultsResponse) obj).d);
    }

    public final int hashCode() {
        return this.d.a.hashCode();
    }

    public final String toString() {
        return "RemoteQuestionBankResultsResponse(models=" + this.d + ")";
    }
}
