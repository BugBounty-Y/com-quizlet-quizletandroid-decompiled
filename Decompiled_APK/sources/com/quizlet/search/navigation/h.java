package com.quizlet.search.navigation;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h extends l {
    public final long a;
    public final List b;

    public h(long j, List studySetIds) {
        Intrinsics.checkNotNullParameter(studySetIds, "studySetIds");
        this.a = j;
        this.b = studySetIds;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return this.a == hVar.a && Intrinsics.b(this.b, hVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "StudySetPreview(studySetId=" + this.a + ", studySetIds=" + this.b + ")";
    }
}
