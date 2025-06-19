package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public final long a;
    public final String b;

    public c(long j, String schoolName) {
        Intrinsics.checkNotNullParameter(schoolName, "schoolName");
        this.a = j;
        this.b = schoolName;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a == cVar.a && Intrinsics.b(this.b, cVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SchoolSelectedData(schoolId=");
        sb.append(this.a);
        sb.append(", schoolName=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
