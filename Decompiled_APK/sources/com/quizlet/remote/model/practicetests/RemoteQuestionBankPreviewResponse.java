package com.quizlet.remote.model.practicetests;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteQuestionBankPreviewResponse extends ApiResponse {
    public final QuestionBankPreviewResponse d;

    public RemoteQuestionBankPreviewResponse(QuestionBankPreviewResponse models) {
        Intrinsics.checkNotNullParameter(models, "models");
        this.d = models;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RemoteQuestionBankPreviewResponse) && Intrinsics.b(this.d, ((RemoteQuestionBankPreviewResponse) obj).d);
    }

    public final int hashCode() {
        return this.d.hashCode();
    }

    public final String toString() {
        return "RemoteQuestionBankPreviewResponse(models=" + this.d + ")";
    }
}
