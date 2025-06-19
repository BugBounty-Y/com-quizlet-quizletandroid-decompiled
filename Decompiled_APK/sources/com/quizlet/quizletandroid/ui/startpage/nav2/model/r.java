package com.quizlet.quizletandroid.ui.startpage.nav2.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class r extends AbstractC4707c {
    public final kotlinx.collections.immutable.b d;
    public final com.quizlet.quizletandroid.ui.globalnav.composable.s e;

    public r(kotlinx.collections.immutable.b getStartedCardData, com.quizlet.quizletandroid.ui.globalnav.composable.s onGetStartedImpression) {
        Intrinsics.checkNotNullParameter(getStartedCardData, "getStartedCardData");
        Intrinsics.checkNotNullParameter(onGetStartedImpression, "onGetStartedImpression");
        this.d = getStartedCardData;
        this.e = onGetStartedImpression;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof r)) {
            return false;
        }
        r rVar = (r) obj;
        return Intrinsics.b(this.d, rVar.d) && this.e.equals(rVar.e);
    }

    @Override // com.quizlet.baserecyclerview.a
    public final /* bridge */ /* synthetic */ Object getItemId() {
        return "empty_state_id";
    }

    public final int hashCode() {
        return this.e.hashCode() + (this.d.hashCode() * 31);
    }

    public final String toString() {
        return "HomeEmptyStateItem(getStartedCardData=" + this.d + ", onGetStartedImpression=" + this.e + ")";
    }
}
