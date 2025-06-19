package com.quizlet.quizletandroid.ui.startpage.nav2.screenstates;

import com.quizlet.db.data.models.persisted.DBStudySet;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f extends s {
    public final DBStudySet a;

    public f(DBStudySet targetSet) {
        Intrinsics.checkNotNullParameter(targetSet, "targetSet");
        this.a = targetSet;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof f) {
            return Intrinsics.b(this.a, ((f) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode() * 31;
    }

    public final String toString() {
        return "GoToStudySet(targetSet=" + this.a + ", destination=null)";
    }
}
