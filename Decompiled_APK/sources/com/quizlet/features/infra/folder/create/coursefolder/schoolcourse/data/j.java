package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class j implements n {
    public final f a;
    public final long b;

    public j(f data, long j) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.a = data;
        this.b = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof j)) {
            return false;
        }
        j jVar = (j) obj;
        return Intrinsics.b(this.a, jVar.a) && this.b == jVar.b;
    }

    public final int hashCode() {
        return Long.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "OnSchoolCourseImpressed(data=" + this.a + ", depth=" + this.b + ")";
    }
}
