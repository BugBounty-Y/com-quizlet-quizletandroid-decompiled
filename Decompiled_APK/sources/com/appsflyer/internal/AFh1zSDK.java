package com.appsflyer.internal;

import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class AFh1zSDK extends AFg1gSDK {

    @NotNull
    private final AFc1dSDK AFAdRevenueData;

    public AFh1zSDK(@NotNull AFc1dSDK aFc1dSDK) {
        Intrinsics.checkNotNullParameter(aFc1dSDK, "");
        this.AFAdRevenueData = aFc1dSDK;
    }

    @Override // com.appsflyer.internal.AFg1gSDK
    public final void e(@NotNull AFg1cSDK aFg1cSDK, @NotNull String str, @NotNull Throwable th, boolean z, boolean z2, boolean z3, boolean z4) {
        Intrinsics.checkNotNullParameter(aFg1cSDK, "");
        Intrinsics.checkNotNullParameter(str, "");
        Intrinsics.checkNotNullParameter(th, "");
        if (z3) {
            if (StringsKt.O(str)) {
                str = "missing label";
            }
            this.AFAdRevenueData.afRDLog().getMediationNetwork(th, withTag$SDK_prodRelease(str, aFg1cSDK));
        }
    }
}
