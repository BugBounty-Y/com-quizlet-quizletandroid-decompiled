package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends f {
    public final long f;
    public final String g;
    public final String h;
    public final b i;
    public final String j;

    /* JADX WARN: Illegal instructions before constructor call */
    public c(long j, String courseTitle, String courseDescription, b courseType, String str, int i) {
        courseType = (i & 8) != 0 ? b.b : courseType;
        String courseSearchSessionId = (i & 32) != 0 ? "" : str;
        Intrinsics.checkNotNullParameter(courseTitle, "courseTitle");
        Intrinsics.checkNotNullParameter(courseDescription, "courseDescription");
        Intrinsics.checkNotNullParameter(courseType, "courseType");
        Intrinsics.checkNotNullParameter(courseSearchSessionId, "courseSearchSessionId");
        super(j, courseTitle, courseDescription, false, courseSearchSessionId);
        this.f = j;
        this.g = courseTitle;
        this.h = courseDescription;
        this.i = courseType;
        this.j = courseSearchSessionId;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.f == cVar.f && Intrinsics.b(this.g, cVar.g) && Intrinsics.b(this.h, cVar.h) && this.i == cVar.i && Intrinsics.b(this.j, cVar.j);
    }

    public final int hashCode() {
        return this.j.hashCode() + d0.g((this.i.hashCode() + d0.e(d0.e(Long.hashCode(this.f) * 31, 31, this.g), 31, this.h)) * 31, 31, false);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Course(courseId=");
        sb.append(this.f);
        sb.append(", courseTitle=");
        sb.append(this.g);
        sb.append(", courseDescription=");
        sb.append(this.h);
        sb.append(", courseType=");
        sb.append(this.i);
        sb.append(", savingCourse=false, courseSearchSessionId=");
        return android.support.v4.media.session.a.t(sb, this.j, ")");
    }
}
