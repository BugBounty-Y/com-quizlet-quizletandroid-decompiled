package com.quizlet.explanations.solution.solutionwall;

import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class i extends b {
    public final l a;
    public final Function0 b;
    public final Function0 c;

    public i(l solutionType, Function0 onGetStartedClick, Function0 onLogInClick) {
        Intrinsics.checkNotNullParameter(solutionType, "solutionType");
        Intrinsics.checkNotNullParameter(onGetStartedClick, "onGetStartedClick");
        Intrinsics.checkNotNullParameter(onLogInClick, "onLogInClick");
        this.a = solutionType;
        this.b = onGetStartedClick;
        this.c = onLogInClick;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return this.a == iVar.a && Intrinsics.b(this.b, iVar.b) && Intrinsics.b(this.c, iVar.c);
    }

    @Override // com.quizlet.baserecyclerview.a
    public final /* bridge */ /* synthetic */ Object getItemId() {
        return "SignUpWallItemId";
    }

    public final int hashCode() {
        return this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        return "SignUpWallItem(solutionType=" + this.a + ", onGetStartedClick=" + this.b + ", onLogInClick=" + this.c + ")";
    }
}
