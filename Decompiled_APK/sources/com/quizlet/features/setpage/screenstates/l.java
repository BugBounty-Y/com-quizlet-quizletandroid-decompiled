package com.quizlet.features.setpage.screenstates;

import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.X;

/* loaded from: classes3.dex */
public final class l {
    public final X a;

    public l(X menuListState) {
        Intrinsics.checkNotNullParameter("STUDY_MODE_OVERFLOW_TAG", "tag");
        Intrinsics.checkNotNullParameter(menuListState, "menuListState");
        this.a = menuListState;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof l)) {
            return false;
        }
        l lVar = (l) obj;
        lVar.getClass();
        return Intrinsics.b(this.a, lVar.a);
    }

    public final int hashCode() {
        return this.a.hashCode() - 1048251747;
    }

    public final String toString() {
        return "Overflowdal(tag=STUDY_MODE_OVERFLOW_TAG, menuListState=" + this.a + ")";
    }
}
