package com.facebook.appevents.iap;

import androidx.compose.animation.d0;
import java.util.Currency;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a {
    public final String a;
    public final double b;
    public final Currency c;

    public a(String eventName, double d, Currency currency) {
        Intrinsics.checkNotNullParameter(eventName, "eventName");
        Intrinsics.checkNotNullParameter(currency, "currency");
        this.a = eventName;
        this.b = d;
        this.c = currency;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Double.compare(this.b, aVar.b) == 0 && Intrinsics.b(this.c, aVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.a(this.b, this.a.hashCode() * 31, 31);
    }

    public final String toString() {
        return "InAppPurchase(eventName=" + this.a + ", amount=" + this.b + ", currency=" + this.c + ')';
    }
}
