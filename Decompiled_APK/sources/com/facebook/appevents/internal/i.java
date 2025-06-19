package com.facebook.appevents.internal;

import android.os.Bundle;
import com.facebook.appevents.q;
import java.math.BigDecimal;
import java.util.Currency;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class i {
    public final BigDecimal a;
    public final Currency b;
    public final Bundle c;
    public final q d;

    public i(BigDecimal purchaseAmount, Currency currency, Bundle param, q operationalData) {
        Intrinsics.checkNotNullParameter(purchaseAmount, "purchaseAmount");
        Intrinsics.checkNotNullParameter(currency, "currency");
        Intrinsics.checkNotNullParameter(param, "param");
        Intrinsics.checkNotNullParameter(operationalData, "operationalData");
        this.a = purchaseAmount;
        this.b = currency;
        this.c = param;
        this.d = operationalData;
    }
}
