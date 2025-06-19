package com.quizlet.upgrade.viewmodel;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i {
    public final com.quizlet.qutils.string.g a;
    public final com.quizlet.qutils.string.f b;
    public final com.quizlet.qutils.string.f c;

    public i(com.quizlet.qutils.string.g planTypeRes, com.quizlet.qutils.string.f planFrequencyRes, com.quizlet.qutils.string.f planInfoRes) {
        Intrinsics.checkNotNullParameter(planTypeRes, "planTypeRes");
        Intrinsics.checkNotNullParameter(planFrequencyRes, "planFrequencyRes");
        Intrinsics.checkNotNullParameter(planInfoRes, "planInfoRes");
        this.a = planTypeRes;
        this.b = planFrequencyRes;
        this.c = planInfoRes;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return this.a.equals(iVar.a) && this.b.equals(iVar.b) && this.c.equals(iVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        return "PlanStringResData(planTypeRes=" + this.a + ", planFrequencyRes=" + this.b + ", planInfoRes=" + this.c + ")";
    }
}
