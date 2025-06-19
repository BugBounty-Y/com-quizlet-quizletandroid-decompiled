package com.quizlet.upgrade.data;

import com.quizlet.quizletandroid.R;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class z implements B {
    public final com.quizlet.data.model.billing.a a;
    public final boolean b;
    public final com.quizlet.qutils.string.f c;

    public z(com.quizlet.data.model.billing.a subscriptionDetails, boolean z) {
        com.quizlet.qutils.string.f fVar;
        Intrinsics.checkNotNullParameter(subscriptionDetails, "subscriptionDetails");
        this.a = subscriptionDetails;
        this.b = z;
        if (subscriptionDetails.a()) {
            Object[] args = new Object[0];
            Intrinsics.checkNotNullParameter(args, "args");
            fVar = new com.quizlet.qutils.string.f(R.string.try_free_and_subscribe, C4933y.P(args));
        } else {
            Object[] args2 = new Object[0];
            Intrinsics.checkNotNullParameter(args2, "args");
            fVar = new com.quizlet.qutils.string.f(R.string.subscribe, C4933y.P(args2));
        }
        this.c = fVar;
    }

    @Override // com.quizlet.upgrade.data.B
    public final boolean a() {
        return this.b;
    }

    @Override // com.quizlet.upgrade.data.B
    public final com.quizlet.qutils.string.f b() {
        return this.c;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof z)) {
            return false;
        }
        z zVar = (z) obj;
        return Intrinsics.b(this.a, zVar.a) && this.b == zVar.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "UpgradeNow(subscriptionDetails=" + this.a + ", shouldShowContinueCTA=" + this.b + ")";
    }
}
