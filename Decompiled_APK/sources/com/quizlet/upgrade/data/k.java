package com.quizlet.upgrade.data;

import com.quizlet.quizletandroid.R;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class k extends m {
    public final J a;
    public final com.quizlet.data.model.billing.a b;
    public final com.quizlet.qutils.string.f c;
    public final com.quizlet.qutils.string.f d;

    public k(J timeline, com.quizlet.data.model.billing.a subscriptionDetails) {
        Intrinsics.checkNotNullParameter(timeline, "timeline");
        Intrinsics.checkNotNullParameter(subscriptionDetails, "subscriptionDetails");
        this.a = timeline;
        this.b = subscriptionDetails;
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        this.c = new com.quizlet.qutils.string.f(R.string.timeline_annual_with_free_trial_section_heading, C4933y.P(args));
        Object[] args2 = new Object[0];
        Intrinsics.checkNotNullParameter(args2, "args");
        this.d = new com.quizlet.qutils.string.f(R.string.try_free_and_subscribe, C4933y.P(args2));
    }

    @Override // com.quizlet.upgrade.data.m
    public final com.quizlet.qutils.string.f a() {
        return this.d;
    }

    @Override // com.quizlet.upgrade.data.m
    public final com.quizlet.data.model.billing.a b() {
        return this.b;
    }

    @Override // com.quizlet.upgrade.data.m
    public final J c() {
        return this.a;
    }

    @Override // com.quizlet.upgrade.data.m
    public final com.quizlet.qutils.string.f d() {
        return this.c;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof k)) {
            return false;
        }
        k kVar = (k) obj;
        return Intrinsics.b(this.a, kVar.a) && Intrinsics.b(this.b, kVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "AnnualWithFreeTrial(timeline=" + this.a + ", subscriptionDetails=" + this.b + ")";
    }
}
