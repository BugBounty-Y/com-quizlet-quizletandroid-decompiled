package com.quizlet.remote.model.practicetests;

import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class PracticeTestMetadata {
    public final String a;
    public final Long b;

    public PracticeTestMetadata(Long l, String creationEntryPoint) {
        Intrinsics.checkNotNullParameter(creationEntryPoint, "creationEntryPoint");
        this.a = creationEntryPoint;
        this.b = l;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PracticeTestMetadata)) {
            return false;
        }
        PracticeTestMetadata practiceTestMetadata = (PracticeTestMetadata) obj;
        return Intrinsics.b(this.a, practiceTestMetadata.a) && Intrinsics.b(this.b, practiceTestMetadata.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        Long l = this.b;
        return iHashCode + (l == null ? 0 : l.hashCode());
    }

    public final String toString() {
        return "PracticeTestMetadata(creationEntryPoint=" + this.a + ", setId=" + this.b + ")";
    }

    public /* synthetic */ PracticeTestMetadata(String str, Long l, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 2) != 0 ? null : l, str);
    }
}
