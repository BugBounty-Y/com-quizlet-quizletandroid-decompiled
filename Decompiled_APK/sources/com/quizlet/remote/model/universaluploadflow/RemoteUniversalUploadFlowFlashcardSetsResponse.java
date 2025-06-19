package com.quizlet.remote.model.universaluploadflow;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteUniversalUploadFlowFlashcardSetsResponse extends ApiResponse {
    public final UniversalUploadFlowFlashcardSetsResponse d;

    public RemoteUniversalUploadFlowFlashcardSetsResponse(UniversalUploadFlowFlashcardSetsResponse models) {
        Intrinsics.checkNotNullParameter(models, "models");
        this.d = models;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RemoteUniversalUploadFlowFlashcardSetsResponse) && Intrinsics.b(this.d, ((RemoteUniversalUploadFlowFlashcardSetsResponse) obj).d);
    }

    public final int hashCode() {
        return this.d.hashCode();
    }

    public final String toString() {
        return "RemoteUniversalUploadFlowFlashcardSetsResponse(models=" + this.d + ")";
    }
}
