package com.quizlet.remote.model.practicetests;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteCopyPracticeTestResponse extends ApiResponse {
    public final RemoteCopyPracticeTestModel d;

    public RemoteCopyPracticeTestResponse(RemoteCopyPracticeTestModel models) {
        Intrinsics.checkNotNullParameter(models, "models");
        this.d = models;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RemoteCopyPracticeTestResponse) && Intrinsics.b(this.d, ((RemoteCopyPracticeTestResponse) obj).d);
    }

    public final int hashCode() {
        return this.d.a.hashCode();
    }

    public final String toString() {
        return "RemoteCopyPracticeTestResponse(models=" + this.d + ")";
    }
}
