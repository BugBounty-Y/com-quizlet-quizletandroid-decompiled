package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class k implements n {
    public final f a;
    public final long b;

    public k(f data, long j) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.a = data;
        this.b = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof k)) {
            return false;
        }
        k kVar = (k) obj;
        return Intrinsics.b(this.a, kVar.a) && this.b == kVar.b;
    }

    public final int hashCode() {
        return Long.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "OnSchoolCourseSelected(data=" + this.a + ", depth=" + this.b + ")";
    }
}
