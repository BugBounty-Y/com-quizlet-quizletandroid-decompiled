package com.quizlet.quizletandroid.ui.globalnav.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m implements o {
    public final k a;

    public m(k tab) {
        Intrinsics.checkNotNullParameter(tab, "tab");
        this.a = tab;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof m) && Intrinsics.b(this.a, ((m) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "OnNavigationItemClick(tab=" + this.a + ")";
    }
}
