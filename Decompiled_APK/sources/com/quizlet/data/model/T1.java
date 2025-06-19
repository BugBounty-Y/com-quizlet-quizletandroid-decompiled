package com.quizlet.data.model;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class T1 {
    public final long a;
    public final List b;

    public T1(long j, List studySetCards) {
        Intrinsics.checkNotNullParameter(studySetCards, "studySetCards");
        this.a = j;
        this.b = studySetCards;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof T1)) {
            return false;
        }
        T1 t1 = (T1) obj;
        return this.a == t1.a && Intrinsics.b(this.b, t1.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "StudySetCardWithSection(sectionTimestamp=" + this.a + ", studySetCards=" + this.b + ")";
    }
}
