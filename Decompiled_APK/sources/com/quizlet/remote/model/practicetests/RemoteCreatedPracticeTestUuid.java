package com.quizlet.remote.model.practicetests;

import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteCreatedPracticeTestUuid {
    public final String a;

    public RemoteCreatedPracticeTestUuid(String practiceTestUuid) {
        Intrinsics.checkNotNullParameter(practiceTestUuid, "practiceTestUuid");
        this.a = practiceTestUuid;
    }
}
