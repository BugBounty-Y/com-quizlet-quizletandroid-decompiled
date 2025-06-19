package com.quizlet.quizletandroid.ui.globalnav.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n implements o {
    public final GlobalNavSuiteItem$Home a;

    public n(GlobalNavSuiteItem$Home tab) {
        Intrinsics.checkNotNullParameter(tab, "tab");
        this.a = tab;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof n) && Intrinsics.b(this.a, ((n) obj).a);
    }

    public final int hashCode() {
        this.a.getClass();
        return 645010614;
    }

    public final String toString() {
        return "Refresh(tab=" + this.a + ")";
    }
}
