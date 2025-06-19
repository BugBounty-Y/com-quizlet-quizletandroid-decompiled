package com.quizlet.explanations.solution.recyclerview.revealbutton;

import androidx.activity.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b implements com.quizlet.baserecyclerview.a {
    public final K a;

    public b(K onShowAllStepsClick) {
        Intrinsics.checkNotNullParameter(onShowAllStepsClick, "onShowAllStepsClick");
        this.a = onShowAllStepsClick;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof b) && this.a.equals(((b) obj).a);
    }

    @Override // com.quizlet.baserecyclerview.a
    public final /* bridge */ /* synthetic */ Object getItemId() {
        return "solutionRevealLayoutId";
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "SolutionRevealButtonItem(onShowAllStepsClick=" + this.a + ")";
    }
}
