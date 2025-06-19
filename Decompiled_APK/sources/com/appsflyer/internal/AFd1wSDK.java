package com.appsflyer.internal;

import com.appsflyer.AppsFlyerLib;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class AFd1wSDK extends AFd1zSDK {

    @NotNull
    public static final AFa1tSDK AFa1tSDK = new AFa1tSDK(null);

    @NotNull
    public static String getRevenue = "https://%smonitorsdk.%s/remote-debug/exception-manager";

    @NotNull
    private final AFd1gSDK getMediationNetwork;

    @Metadata
    public static final class AFa1tSDK {
        private AFa1tSDK() {
        }

        public /* synthetic */ AFa1tSDK(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AFd1wSDK(@NotNull byte[] bArr, Map<String, String> map, int i) {
        super(bArr, map, i);
        Intrinsics.checkNotNullParameter(bArr, "");
        this.getMediationNetwork = AFd1gSDK.JSON;
    }

    @Override // com.appsflyer.internal.AFd1zSDK
    @NotNull
    public final String getCurrencyIso4217Code() {
        String str = String.format(getRevenue, AppsFlyerLib.getInstance().getHostPrefix(), ((com.appsflyer.internal.AFa1tSDK) com.appsflyer.internal.AFa1tSDK.getMonetizationNetwork(new Object[0], -631580017, 631580017, (int) System.currentTimeMillis())).getHostName());
        Intrinsics.checkNotNullExpressionValue(str, "");
        return str;
    }

    @Override // com.appsflyer.internal.AFd1zSDK
    @NotNull
    public final AFd1gSDK getRevenue() {
        return this.getMediationNetwork;
    }

    @Override // com.appsflyer.internal.AFd1zSDK
    @NotNull
    public final String getCurrencyIso4217Code(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "");
        return AFd1rSDK.AFAdRevenueData(str);
    }
}
