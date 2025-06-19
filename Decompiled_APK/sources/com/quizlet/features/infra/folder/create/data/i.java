package com.quizlet.features.infra.folder.create.data;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i {
    public final long a;
    public final String b;
    public final long c;
    public final String d;

    public i(long j, long j2, String schoolName, String str) {
        Intrinsics.checkNotNullParameter(schoolName, "schoolName");
        this.a = j;
        this.b = schoolName;
        this.c = j2;
        this.d = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return this.a == iVar.a && Intrinsics.b(this.b, iVar.b) && this.c == iVar.c && Intrinsics.b(this.d, iVar.d);
    }

    public final int hashCode() {
        int iD = d0.d(d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c);
        String str = this.d;
        return iD + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SchoolCourseUiData(schoolId=");
        sb.append(this.a);
        sb.append(", schoolName=");
        sb.append(this.b);
        sb.append(", courseId=");
        sb.append(this.c);
        sb.append(", courseName=");
        return android.support.v4.media.session.a.t(sb, this.d, ")");
    }
}
