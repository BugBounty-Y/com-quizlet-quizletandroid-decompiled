package com.appsflyer.internal;

import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class AFd1mSDK extends AFd1zSDK {

    @NotNull
    private final AFd1gSDK areAllFieldsValid;
    private final boolean getMediationNetwork;

    @NotNull
    public AFc1pSDK getRevenue;

    public /* synthetic */ AFd1mSDK(AFc1pSDK aFc1pSDK, byte[] bArr, Map map, int i, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(aFc1pSDK, bArr, (i2 & 4) != 0 ? null : map, (i2 & 8) != 0 ? 2000 : i);
    }

    @Override // com.appsflyer.internal.AFd1zSDK
    @NotNull
    public final String getCurrencyIso4217Code() {
        AFj1fSDK aFj1fSDK = new AFj1fSDK(this.getRevenue, null, 2, null);
        return aFj1fSDK.getCurrencyIso4217Code(aFj1fSDK.getMonetizationNetwork.AFAdRevenueData(AFj1fSDK.component4));
    }

    @Override // com.appsflyer.internal.AFd1zSDK
    public final boolean getMediationNetwork() {
        return this.getMediationNetwork;
    }

    @Override // com.appsflyer.internal.AFd1zSDK
    @NotNull
    public final AFd1gSDK getRevenue() {
        return this.areAllFieldsValid;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    private AFd1mSDK(@NotNull AFc1pSDK aFc1pSDK, @NotNull byte[] bArr, Map<String, String> map, int i) {
        super(bArr, map, i);
        Intrinsics.checkNotNullParameter(aFc1pSDK, "");
        Intrinsics.checkNotNullParameter(bArr, "");
        this.getRevenue = aFc1pSDK;
        this.areAllFieldsValid = AFd1gSDK.OCTET_STREAM;
    }

    @Override // com.appsflyer.internal.AFd1zSDK
    @NotNull
    public final String getCurrencyIso4217Code(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "");
        return "[RD]: " + str;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public AFd1mSDK(@NotNull AFc1pSDK aFc1pSDK, @NotNull byte[] bArr) {
        this(aFc1pSDK, bArr, null, 0, 12, null);
        Intrinsics.checkNotNullParameter(aFc1pSDK, "");
        Intrinsics.checkNotNullParameter(bArr, "");
    }
}
