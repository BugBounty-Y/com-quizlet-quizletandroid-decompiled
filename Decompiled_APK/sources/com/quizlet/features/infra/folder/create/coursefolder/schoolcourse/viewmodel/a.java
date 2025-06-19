package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final long a;
    public final String b;

    public a(long j, String courseTitle) {
        Intrinsics.checkNotNullParameter(courseTitle, "courseTitle");
        this.a = j;
        this.b = courseTitle;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && Intrinsics.b(this.b, aVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CourseSelectedData(courseId=");
        sb.append(this.a);
        sb.append(", courseTitle=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
