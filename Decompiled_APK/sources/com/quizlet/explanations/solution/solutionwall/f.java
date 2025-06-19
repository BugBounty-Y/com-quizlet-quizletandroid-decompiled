package com.quizlet.explanations.solution.solutionwall;

import com.quizlet.data.model.X;
import com.quizlet.quizletandroid.R;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class f extends g {
    public final X a;
    public final com.quizlet.explanations.questiondetail.ui.c b;

    public f(X meteringInfo, com.quizlet.explanations.questiondetail.ui.c onSubscribeClick) {
        Intrinsics.checkNotNullParameter(meteringInfo, "meteringInfo");
        Intrinsics.checkNotNullParameter(onSubscribeClick, "onSubscribeClick");
        this.a = meteringInfo;
        this.b = onSubscribeClick;
    }

    @Override // com.quizlet.explanations.solution.solutionwall.g
    public final Function0 a() {
        return this.b;
    }

    @Override // com.quizlet.explanations.solution.solutionwall.g
    public final com.quizlet.qutils.string.f b() {
        if (this.a.b == 0) {
            Object[] args = new Object[0];
            Intrinsics.checkNotNullParameter(args, "args");
            return new com.quizlet.qutils.string.f(R.string.explanations_metering_question_paywall_title_zero_threshold, C4933y.P(args));
        }
        Object[] args2 = new Object[0];
        Intrinsics.checkNotNullParameter(args2, "args");
        return new com.quizlet.qutils.string.f(R.string.explanations_metering_question_paywall_title_nonzero_threshold, C4933y.P(args2));
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return Intrinsics.b(this.a, fVar.a) && this.b.equals(fVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "Question(meteringInfo=" + this.a + ", onSubscribeClick=" + this.b + ")";
    }
}
