package com.quizlet.upgrade.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class E {
    public final com.quizlet.qutils.string.f a;
    public final com.quizlet.qutils.string.f b;
    public final com.quizlet.qutils.string.f c;
    public final com.quizlet.qutils.string.f d;
    public final String e;
    public final D f;

    public E(com.quizlet.qutils.string.f fVar, com.quizlet.qutils.string.f cost, com.quizlet.qutils.string.f fVar2, com.quizlet.qutils.string.f fVar3, String str, D d) {
        Intrinsics.checkNotNullParameter(cost, "cost");
        this.a = fVar;
        this.b = cost;
        this.c = fVar2;
        this.d = fVar3;
        this.e = str;
        this.f = d;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof E)) {
            return false;
        }
        E e = (E) obj;
        return Intrinsics.b(this.a, e.a) && this.b.equals(e.b) && Intrinsics.b(this.c, e.c) && Intrinsics.b(this.d, e.d) && Intrinsics.b(this.e, e.e) && Intrinsics.b(this.f, e.f);
    }

    public final int hashCode() {
        com.quizlet.qutils.string.f fVar = this.a;
        int iHashCode = (this.b.hashCode() + ((fVar == null ? 0 : fVar.hashCode()) * 31)) * 31;
        com.quizlet.qutils.string.f fVar2 = this.c;
        int iHashCode2 = (iHashCode + (fVar2 == null ? 0 : fVar2.hashCode())) * 31;
        com.quizlet.qutils.string.f fVar3 = this.d;
        int iHashCode3 = (iHashCode2 + (fVar3 == null ? 0 : fVar3.hashCode())) * 31;
        String str = this.e;
        int iHashCode4 = (iHashCode3 + (str == null ? 0 : str.hashCode())) * 31;
        D d = this.f;
        return iHashCode4 + (d != null ? d.hashCode() : 0);
    }

    public final String toString() {
        return "UpgradeHeaderState(headerSubscriptionPeriod=" + this.a + ", cost=" + this.b + ", annualMonthlyCost=" + this.c + ", currentSubscriptionDetails=" + this.d + ", manageSubsLinkDestination=" + this.e + ", upgradeHeaderFreeTrialDetails=" + this.f + ")";
    }
}
