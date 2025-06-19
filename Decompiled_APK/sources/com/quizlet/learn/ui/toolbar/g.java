package com.quizlet.learn.ui.toolbar;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g extends j {
    public final d b;
    public final com.google.firebase.crashlytics.internal.common.i c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(d progressState, com.google.firebase.crashlytics.internal.common.i iVar) {
        super(true);
        Intrinsics.checkNotNullParameter(progressState, "progressState");
        this.b = progressState;
        this.c = iVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return Intrinsics.b(this.b, gVar.b) && Intrinsics.b(this.c, gVar.c);
    }

    public final int hashCode() {
        int iHashCode = this.b.hashCode() * 31;
        com.google.firebase.crashlytics.internal.common.i iVar = this.c;
        return iHashCode + (iVar == null ? 0 : iVar.hashCode());
    }

    public final String toString() {
        return "Learn(progressState=" + this.b + ", onAnimationComplete=" + this.c + ")";
    }
}
