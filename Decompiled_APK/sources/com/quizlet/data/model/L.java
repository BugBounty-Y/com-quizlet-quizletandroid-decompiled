package com.quizlet.data.model;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class L {
    public final Object a;
    public final String b;

    public L(String searchSessionId, List courses) {
        Intrinsics.checkNotNullParameter(courses, "courses");
        Intrinsics.checkNotNullParameter(searchSessionId, "searchSessionId");
        this.a = courses;
        this.b = searchSessionId;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof L)) {
            return false;
        }
        L l = (L) obj;
        return Intrinsics.b(this.a, l.a) && this.b.equals(l.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CourseSearchResults(courses=");
        sb.append(this.a);
        sb.append(", searchSessionId=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
