package com.quizlet.features.setpage.screenstates;

import com.quizlet.db.data.models.persisted.DBStudySet;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class x extends A {
    public final DBStudySet a;

    public x(DBStudySet set) {
        Intrinsics.checkNotNullParameter(set, "set");
        this.a = set;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof x) && Intrinsics.b(this.a, ((x) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "EditSet(set=" + this.a + ")";
    }
}
