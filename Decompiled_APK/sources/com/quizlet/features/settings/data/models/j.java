package com.quizlet.features.settings.data.models;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class j implements k {
    public final int a;
    public final Integer b;

    public j(int i, Integer num) {
        this.a = i;
        this.b = num;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof j)) {
            return false;
        }
        j jVar = (j) obj;
        return this.a == jVar.a && Intrinsics.b(this.b, jVar.b);
    }

    public final int hashCode() {
        int iHashCode = Integer.hashCode(this.a) * 31;
        Integer num = this.b;
        return iHashCode + (num == null ? 0 : num.hashCode());
    }

    public final String toString() {
        return "Plus(userUpgradeTypeLabel=" + this.a + ", subscriptionFrequencyLabel=" + this.b + ")";
    }
}
