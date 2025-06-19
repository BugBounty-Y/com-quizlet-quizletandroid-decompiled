package com.quizlet.explanations.solution.solutionwall;

import com.quizlet.quizletandroid.R;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class e extends g {
    public final com.quizlet.explanations.textbook.exercisedetail.ui.a a;

    public e(com.quizlet.explanations.textbook.exercisedetail.ui.a onSubscribeClick) {
        Intrinsics.checkNotNullParameter(onSubscribeClick, "onSubscribeClick");
        this.a = onSubscribeClick;
    }

    @Override // com.quizlet.explanations.solution.solutionwall.g
    public final Function0 a() {
        return this.a;
    }

    @Override // com.quizlet.explanations.solution.solutionwall.g
    public final com.quizlet.qutils.string.f b() {
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        return new com.quizlet.qutils.string.f(R.string.explanations_metering_exercise_paywall_title, C4933y.P(args));
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof e) && this.a.equals(((e) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Exercise(onSubscribeClick=" + this.a + ")";
    }
}
