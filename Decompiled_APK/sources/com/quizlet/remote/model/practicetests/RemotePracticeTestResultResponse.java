package com.quizlet.remote.model.practicetests;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemotePracticeTestResultResponse extends ApiResponse {
    public final PracticeTestResultResponse d;

    public RemotePracticeTestResultResponse(PracticeTestResultResponse models) {
        Intrinsics.checkNotNullParameter(models, "models");
        this.d = models;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RemotePracticeTestResultResponse) && Intrinsics.b(this.d, ((RemotePracticeTestResultResponse) obj).d);
    }

    public final int hashCode() {
        return this.d.hashCode();
    }

    public final String toString() {
        return "RemotePracticeTestResultResponse(models=" + this.d + ")";
    }
}
