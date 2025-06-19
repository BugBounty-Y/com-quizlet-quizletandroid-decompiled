package com.quizlet.remote.model.practicetests;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteQuestionBanksResponse extends ApiResponse {
    public final QuestionBanksResponse d;

    public RemoteQuestionBanksResponse(QuestionBanksResponse questionBanksResponse) {
        this.d = questionBanksResponse;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RemoteQuestionBanksResponse) && Intrinsics.b(this.d, ((RemoteQuestionBanksResponse) obj).d);
    }

    public final int hashCode() {
        QuestionBanksResponse questionBanksResponse = this.d;
        if (questionBanksResponse == null) {
            return 0;
        }
        return questionBanksResponse.a.hashCode();
    }

    public final String toString() {
        return "RemoteQuestionBanksResponse(models=" + this.d + ")";
    }

    public /* synthetic */ RemoteQuestionBanksResponse(QuestionBanksResponse questionBanksResponse, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : questionBanksResponse);
    }
}
