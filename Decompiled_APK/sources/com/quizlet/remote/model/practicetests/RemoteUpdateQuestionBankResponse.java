package com.quizlet.remote.model.practicetests;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteUpdateQuestionBankResponse extends ApiResponse {
    public final RemoteUpdateQuestionBankModel d;

    public RemoteUpdateQuestionBankResponse(RemoteUpdateQuestionBankModel models) {
        Intrinsics.checkNotNullParameter(models, "models");
        this.d = models;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RemoteUpdateQuestionBankResponse) && Intrinsics.b(this.d, ((RemoteUpdateQuestionBankResponse) obj).d);
    }

    public final int hashCode() {
        return this.d.a.hashCode();
    }

    public final String toString() {
        return "RemoteUpdateQuestionBankResponse(models=" + this.d + ")";
    }
}
