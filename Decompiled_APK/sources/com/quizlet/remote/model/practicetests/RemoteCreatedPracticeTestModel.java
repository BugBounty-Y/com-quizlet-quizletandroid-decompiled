package com.quizlet.remote.model.practicetests;

import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteCreatedPracticeTestModel {
    public final List a;

    public RemoteCreatedPracticeTestModel(List practiceTest) {
        Intrinsics.checkNotNullParameter(practiceTest, "practiceTest");
        this.a = practiceTest;
    }
}
