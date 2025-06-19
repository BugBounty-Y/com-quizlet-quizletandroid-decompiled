package com.quizlet.quizletandroid.ui.startpage.nav2.screenstates;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m implements r {
    public final v a;

    public m(v adapterOrder) {
        Intrinsics.checkNotNullParameter(adapterOrder, "adapterOrder");
        this.a = adapterOrder;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof m) && Intrinsics.b(this.a, ((m) obj).a);
    }

    public final int hashCode() {
        return this.a.a.hashCode();
    }

    public final String toString() {
        return "ContentState(adapterOrder=" + this.a + ")";
    }
}
