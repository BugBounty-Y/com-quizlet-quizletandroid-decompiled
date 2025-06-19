package com.quizlet.upgrade.manager;

import com.quizlet.upgrade.data.I;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements d {
    public final I a;

    public b(I purchaseData) {
        Intrinsics.checkNotNullParameter(purchaseData, "purchaseData");
        this.a = purchaseData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof b) && Intrinsics.b(this.a, ((b) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "StartPurchase(purchaseData=" + this.a + ")";
    }
}
