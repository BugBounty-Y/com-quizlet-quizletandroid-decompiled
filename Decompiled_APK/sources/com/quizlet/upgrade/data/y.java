package com.quizlet.upgrade.data;

import com.quizlet.quizletandroid.R;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class y implements B {
    public final boolean a;
    public final C4841i b;
    public final com.quizlet.qutils.string.f c;

    public y(boolean z, C4841i c4841i) {
        this.a = z;
        this.b = c4841i;
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        this.c = new com.quizlet.qutils.string.f(R.string.see_plans, C4933y.P(args));
    }

    @Override // com.quizlet.upgrade.data.B
    public final boolean a() {
        return this.a;
    }

    @Override // com.quizlet.upgrade.data.B
    public final com.quizlet.qutils.string.f b() {
        return this.c;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof y)) {
            return false;
        }
        y yVar = (y) obj;
        return this.a == yVar.a && Intrinsics.b(this.b, yVar.b);
    }

    public final int hashCode() {
        int iHashCode = Boolean.hashCode(this.a) * 31;
        C4841i c4841i = this.b;
        return iHashCode + (c4841i == null ? 0 : Integer.hashCode(c4841i.a));
    }

    public final String toString() {
        return "SeePlans(shouldShowContinueCTA=" + this.a + ", seePlansFreeTrialString=" + this.b + ")";
    }
}
