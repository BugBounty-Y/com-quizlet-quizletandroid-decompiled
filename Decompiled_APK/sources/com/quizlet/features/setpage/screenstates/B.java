package com.quizlet.features.setpage.screenstates;

import com.quizlet.db.data.models.persisted.DBStudySet;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class B extends E {
    public final DBStudySet a;

    public B(DBStudySet set) {
        Intrinsics.checkNotNullParameter(set, "set");
        this.a = set;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof B) && Intrinsics.b(this.a, ((B) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Check(set=" + this.a + ")";
    }
}
