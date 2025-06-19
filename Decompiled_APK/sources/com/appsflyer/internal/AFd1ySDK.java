package com.appsflyer.internal;

import java.util.Map;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class AFd1ySDK implements AFd1xSDK {

    @NotNull
    private final AFc1aSDK getRevenue;

    public AFd1ySDK(@NotNull AFc1aSDK aFc1aSDK) {
        Intrinsics.checkNotNullParameter(aFc1aSDK, "");
        this.getRevenue = aFc1aSDK;
    }

    @Override // com.appsflyer.internal.AFd1xSDK
    public final void getMediationNetwork(@NotNull byte[] bArr, Map<String, String> map, int i) {
        Intrinsics.checkNotNullParameter(bArr, "");
        Intrinsics.checkNotNullParameter(bArr, "");
        if (new AFd1wSDK(bArr, map, 2000).getMonetizationNetwork()) {
            this.getRevenue.getMonetizationNetwork();
        }
    }
}
