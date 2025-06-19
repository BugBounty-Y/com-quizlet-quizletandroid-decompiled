package com.quizlet.remote.model.practicetests;

import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class PracticeTestSchool {
    public final int a;
    public final String b;

    public PracticeTestSchool(int i, String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        this.a = i;
        this.b = name;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PracticeTestSchool)) {
            return false;
        }
        PracticeTestSchool practiceTestSchool = (PracticeTestSchool) obj;
        return this.a == practiceTestSchool.a && Intrinsics.b(this.b, practiceTestSchool.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "PracticeTestSchool(id=" + this.a + ", name=" + this.b + ")";
    }
}
