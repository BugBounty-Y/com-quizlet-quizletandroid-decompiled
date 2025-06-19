package com.quizlet.remote.model.practicetests;

import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.K;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteCopyPracticeTestModel {
    public final List a;

    public RemoteCopyPracticeTestModel(List practiceTest) {
        Intrinsics.checkNotNullParameter(practiceTest, "practiceTest");
        this.a = practiceTest;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RemoteCopyPracticeTestModel) && Intrinsics.b(this.a, ((RemoteCopyPracticeTestModel) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("RemoteCopyPracticeTestModel(practiceTest="), this.a);
    }

    public RemoteCopyPracticeTestModel(List list, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? K.a : list);
    }
}
