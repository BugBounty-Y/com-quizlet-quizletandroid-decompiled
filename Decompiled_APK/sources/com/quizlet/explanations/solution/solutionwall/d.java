package com.quizlet.explanations.solution.solutionwall;

import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d extends b {
    public final Function0 a;

    public d(Function0 onContactUsClick) {
        Intrinsics.checkNotNullParameter(onContactUsClick, "onContactUsClick");
        this.a = onContactUsClick;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof d) && Intrinsics.b(this.a, ((d) obj).a);
    }

    @Override // com.quizlet.baserecyclerview.a
    public final /* bridge */ /* synthetic */ Object getItemId() {
        return "LimitedContentWallItemId";
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "LimitedContentWallItem(onContactUsClick=" + this.a + ")";
    }
}
