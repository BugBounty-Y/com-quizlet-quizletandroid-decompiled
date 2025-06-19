package com.snowplowanalytics.core.tracker;

import android.net.NetworkInfo;
import com.amazon.device.ads.DTBMetricsConfiguration;
import java.util.Locale;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;
import kotlin.text.D;

/* loaded from: classes3.dex */
public final class g extends r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ i b;
    public final /* synthetic */ NetworkInfo c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ g(i iVar, NetworkInfo networkInfo, int i) {
        super(0);
        this.a = i;
        this.b = iVar;
        this.c = networkInfo;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.c.getClass();
                NetworkInfo networkInfo = this.c;
                if (networkInfo != null) {
                    String typeName = networkInfo.getTypeName();
                    Intrinsics.checkNotNullExpressionValue(typeName, "networkInfo.typeName");
                    Locale locale = Locale.getDefault();
                    Intrinsics.checkNotNullExpressionValue(locale, "getDefault()");
                    String lowerCase = typeName.toLowerCase(locale);
                    Intrinsics.checkNotNullExpressionValue(lowerCase, "this as java.lang.String).toLowerCase(locale)");
                    if (Intrinsics.b(lowerCase, DTBMetricsConfiguration.APSMETRICS_LEVEL2_KEY) ? true : Intrinsics.b(lowerCase, "wifi")) {
                        return lowerCase;
                    }
                }
                return "offline";
            default:
                this.b.c.getClass();
                NetworkInfo networkInfo2 = this.c;
                if (networkInfo2 == null || !D.l(networkInfo2.getTypeName(), "MOBILE", true)) {
                    return null;
                }
                return networkInfo2.getSubtypeName();
        }
    }
}
