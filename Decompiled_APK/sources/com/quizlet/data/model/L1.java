package com.quizlet.data.model;

import com.quizlet.generated.enums.EnumC4479f;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class L1 {
    public final int a;
    public final EnumC4479f b;

    public L1(int i, EnumC4479f type) {
        Intrinsics.checkNotNullParameter(type, "type");
        this.a = i;
        this.b = type;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof L1)) {
            return false;
        }
        L1 l1 = (L1) obj;
        return this.a == l1.a && this.b == l1.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "StreakStatusData(amount=" + this.a + ", type=" + this.b + ")";
    }
}
