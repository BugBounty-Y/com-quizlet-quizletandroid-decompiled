package com.quizlet.remote.model.practicetests;

import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class PracticeTestCourse {
    public final int a;
    public final String b;

    public PracticeTestCourse(int i, String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        this.a = i;
        this.b = name;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PracticeTestCourse)) {
            return false;
        }
        PracticeTestCourse practiceTestCourse = (PracticeTestCourse) obj;
        return this.a == practiceTestCourse.a && Intrinsics.b(this.b, practiceTestCourse.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "PracticeTestCourse(id=" + this.a + ", name=" + this.b + ")";
    }
}
