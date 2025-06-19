package com.quizlet.remote.model.practicetests;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteCreatedPracticeTestResponse extends ApiResponse {
    public final RemoteCreatedPracticeTestModel d;

    public RemoteCreatedPracticeTestResponse(RemoteCreatedPracticeTestModel remoteCreatedPracticeTestModel) {
        this.d = remoteCreatedPracticeTestModel;
    }

    public /* synthetic */ RemoteCreatedPracticeTestResponse(RemoteCreatedPracticeTestModel remoteCreatedPracticeTestModel, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : remoteCreatedPracticeTestModel);
    }
}
