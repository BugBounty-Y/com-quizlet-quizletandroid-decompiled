package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class S {
    public final boolean a;
    public final String b;
    public final C4185z0 c;
    public final Integer d;

    public S(boolean z, String str, C4185z0 c4185z0) {
        Integer numValueOf;
        this.a = z;
        this.b = str;
        this.c = c4185z0;
        Integer num = c4185z0.b;
        if (num != null) {
            int iIntValue = num.intValue();
            Integer num2 = c4185z0.a;
            numValueOf = Integer.valueOf(iIntValue - (num2 != null ? num2.intValue() : 0));
        } else {
            numValueOf = null;
        }
        this.d = numValueOf;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof S)) {
            return false;
        }
        S s = (S) obj;
        return this.a == s.a && Intrinsics.b(this.b, s.b) && Intrinsics.b(this.c, s.c);
    }

    public final int hashCode() {
        int iHashCode = Boolean.hashCode(this.a) * 31;
        String str = this.b;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        C4185z0 c4185z0 = this.c;
        return iHashCode2 + (c4185z0 != null ? c4185z0.hashCode() : 0);
    }

    public final String toString() {
        return "EntitlementData(canUseFeature=" + this.a + ", overrideReason=" + this.b + ", meteringMeta=" + this.c + ")";
    }
}
