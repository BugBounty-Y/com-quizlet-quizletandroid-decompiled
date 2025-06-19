package com.quizlet.remote.model.practicetests;

import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteCopyPracticeTestUuid {
    public final String a;

    public RemoteCopyPracticeTestUuid(String practiceTestUuid) {
        Intrinsics.checkNotNullParameter(practiceTestUuid, "practiceTestUuid");
        this.a = practiceTestUuid;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RemoteCopyPracticeTestUuid) && Intrinsics.b(this.a, ((RemoteCopyPracticeTestUuid) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("RemoteCopyPracticeTestUuid(practiceTestUuid="), this.a, ")");
    }
}
