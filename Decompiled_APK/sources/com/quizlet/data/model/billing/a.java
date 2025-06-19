package com.quizlet.data.model.billing;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final String a;
    public final long b;
    public final String c;
    public final String d;
    public final String e;
    public final String f;
    public final boolean g;

    public a(String sku, long j, String priceCurrencyCode, String name, String subscriptionPeriod, String str, boolean z) {
        Intrinsics.checkNotNullParameter(sku, "sku");
        Intrinsics.checkNotNullParameter(priceCurrencyCode, "priceCurrencyCode");
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(subscriptionPeriod, "subscriptionPeriod");
        this.a = sku;
        this.b = j;
        this.c = priceCurrencyCode;
        this.d = name;
        this.e = subscriptionPeriod;
        this.f = str;
        this.g = z;
    }

    public final boolean a() {
        String str;
        return this.g && (str = this.f) != null && str.length() > 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && this.b == aVar.b && Intrinsics.b(this.c, aVar.c) && Intrinsics.b(this.d, aVar.d) && Intrinsics.b(this.e, aVar.e) && Intrinsics.b(this.f, aVar.f) && this.g == aVar.g;
    }

    public final int hashCode() {
        int iE = d0.e(d0.e(d0.e(d0.d(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e);
        String str = this.f;
        return Boolean.hashCode(this.g) + ((iE + (str == null ? 0 : str.hashCode())) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SubscriptionDetails(sku=");
        sb.append(this.a);
        sb.append(", priceAmountMicros=");
        sb.append(this.b);
        sb.append(", priceCurrencyCode=");
        sb.append(this.c);
        sb.append(", name=");
        sb.append(this.d);
        sb.append(", subscriptionPeriod=");
        sb.append(this.e);
        sb.append(", freeTrialPeriod=");
        sb.append(this.f);
        sb.append(", isEligibleForFreeTrial=");
        return android.support.v4.media.session.a.o(")", sb, this.g);
    }
}
