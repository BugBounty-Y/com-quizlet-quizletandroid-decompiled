package com.quizlet.remote.model.practicetests;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemotePracticeTestResponse extends ApiResponse {
    public final PracticeTestResponse d;

    public RemotePracticeTestResponse(PracticeTestResponse practiceTestResponse) {
        this.d = practiceTestResponse;
    }

    public /* synthetic */ RemotePracticeTestResponse(PracticeTestResponse practiceTestResponse, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : practiceTestResponse);
    }
}
