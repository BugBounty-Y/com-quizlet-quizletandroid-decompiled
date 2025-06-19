package com.quizlet.quizletandroid.ui.startpage.nav2.screenstates;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n implements r {
    public final kotlinx.collections.immutable.b a;
    public final com.quizlet.quizletandroid.ui.globalnav.composable.s b;

    public n(kotlinx.collections.immutable.b getStartedCardData, com.quizlet.quizletandroid.ui.globalnav.composable.s onGetStartedImpression) {
        Intrinsics.checkNotNullParameter(getStartedCardData, "getStartedCardData");
        Intrinsics.checkNotNullParameter(onGetStartedImpression, "onGetStartedImpression");
        this.a = getStartedCardData;
        this.b = onGetStartedImpression;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof n)) {
            return false;
        }
        n nVar = (n) obj;
        return Intrinsics.b(this.a, nVar.a) && this.b.equals(nVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "EmptyHomeState(getStartedCardData=" + this.a + ", onGetStartedImpression=" + this.b + ")";
    }
}
