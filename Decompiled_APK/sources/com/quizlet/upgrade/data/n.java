package com.quizlet.upgrade.data;

import android.content.Context;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import java.math.BigDecimal;
import java.text.NumberFormat;
import java.util.Currency;
import java.util.Locale;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n implements com.quizlet.qutils.string.g {
    public final com.quizlet.data.model.billing.c a;

    public n(com.quizlet.data.model.billing.c price) {
        Intrinsics.checkNotNullParameter(price, "price");
        this.a = price;
    }

    @Override // com.quizlet.qutils.string.g
    public final String a(Context context) {
        return AbstractC3053s1.e(this, context);
    }

    @Override // com.quizlet.qutils.string.g
    public final String b(InterfaceC0806l interfaceC0806l) {
        return AbstractC3053s1.g(this, interfaceC0806l);
    }

    @Override // com.quizlet.qutils.string.g
    public final CharSequence c(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        Locale locale = context.getResources().getConfiguration().getLocales().get(0);
        Intrinsics.d(locale);
        com.quizlet.data.model.billing.c cVar = this.a;
        Intrinsics.checkNotNullParameter(cVar, "<this>");
        Intrinsics.checkNotNullParameter(locale, "locale");
        Intrinsics.checkNotNullParameter(cVar, "<this>");
        BigDecimal bigDecimalDivide = new BigDecimal(cVar.a).divide(BigDecimal.valueOf(1000000L));
        Intrinsics.checkNotNullExpressionValue(bigDecimalDivide, "divide(...)");
        NumberFormat currencyInstance = NumberFormat.getCurrencyInstance(locale);
        currencyInstance.setCurrency(Currency.getInstance(cVar.b));
        String str = currencyInstance.format(bigDecimalDivide);
        Intrinsics.checkNotNullExpressionValue(str, "format(...)");
        return str;
    }

    @Override // com.quizlet.qutils.string.g
    public final CharSequence d(InterfaceC0806l interfaceC0806l, int i) {
        return AbstractC3053s1.b(this, interfaceC0806l);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof n) && Intrinsics.b(this.a, ((n) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "SubscriptionPriceStringData(price=" + this.a + ")";
    }
}
