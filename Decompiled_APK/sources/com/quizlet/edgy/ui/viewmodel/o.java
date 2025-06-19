package com.quizlet.edgy.ui.viewmodel;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class o extends s {
    public final com.quizlet.edgy.ui.recyclerview.adapter.i a;
    public final r b;

    public o(com.quizlet.edgy.ui.recyclerview.adapter.i searchSchoolItem) {
        Intrinsics.checkNotNullParameter(searchSchoolItem, "searchSchoolItem");
        this.a = searchSchoolItem;
        this.b = new r(true, false, false, true, false, EnumC4212m.g, false, true, false, true, true, true);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof o) && Intrinsics.b(this.a, ((o) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "SchoolSelected(searchSchoolItem=" + this.a + ")";
    }
}
