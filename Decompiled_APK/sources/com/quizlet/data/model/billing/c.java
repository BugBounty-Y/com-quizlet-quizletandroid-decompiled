package com.quizlet.data.model.billing;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c {
    public final long a;
    public final String b;

    public c(long j, String priceCurrencyCode) {
        Intrinsics.checkNotNullParameter(priceCurrencyCode, "priceCurrencyCode");
        this.a = j;
        this.b = priceCurrencyCode;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a == cVar.a && Intrinsics.b(this.b, cVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SubscriptionPrice(priceAmountMicros=");
        sb.append(this.a);
        sb.append(", priceCurrencyCode=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
