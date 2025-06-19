package com.quizlet.remote.model.practicetests;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteUpdateGradedAnswerResponse extends ApiResponse {
    public final RemoteUpdateGradedAnswerModel d;

    public RemoteUpdateGradedAnswerResponse(RemoteUpdateGradedAnswerModel models) {
        Intrinsics.checkNotNullParameter(models, "models");
        this.d = models;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RemoteUpdateGradedAnswerResponse) && Intrinsics.b(this.d, ((RemoteUpdateGradedAnswerResponse) obj).d);
    }

    public final int hashCode() {
        return this.d.a.hashCode();
    }

    public final String toString() {
        return "RemoteUpdateGradedAnswerResponse(models=" + this.d + ")";
    }
}
