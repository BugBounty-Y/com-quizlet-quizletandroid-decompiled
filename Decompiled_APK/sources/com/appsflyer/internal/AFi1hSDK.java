package com.appsflyer.internal;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class AFi1hSDK {
    public final long AFAdRevenueData;
    public final String getCurrencyIso4217Code;
    public final String getMonetizationNetwork;
    public final long getRevenue;

    public AFi1hSDK(long j, long j2, String str, String str2) {
        this.AFAdRevenueData = j;
        this.getRevenue = j2;
        this.getCurrencyIso4217Code = str;
        this.getMonetizationNetwork = str2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof AFi1hSDK)) {
            return false;
        }
        AFi1hSDK aFi1hSDK = (AFi1hSDK) obj;
        return this.AFAdRevenueData == aFi1hSDK.AFAdRevenueData && this.getRevenue == aFi1hSDK.getRevenue && Intrinsics.b(this.getCurrencyIso4217Code, aFi1hSDK.getCurrencyIso4217Code) && Intrinsics.b(this.getMonetizationNetwork, aFi1hSDK.getMonetizationNetwork);
    }

    public final int hashCode() {
        int iD = d0.d(Long.hashCode(this.AFAdRevenueData) * 31, 31, this.getRevenue);
        String str = this.getCurrencyIso4217Code;
        int iHashCode = (iD + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.getMonetizationNetwork;
        return iHashCode + (str2 != null ? str2.hashCode() : 0);
    }

    @NotNull
    public final String toString() {
        long j = this.AFAdRevenueData;
        long j2 = this.getRevenue;
        String str = this.getCurrencyIso4217Code;
        String str2 = this.getMonetizationNetwork;
        StringBuilder sbT = d0.t(j, "PlayIntegrityApiData(piaTimestamp=", ", ttrMillis=");
        sbT.append(j2);
        sbT.append(", piaToken=");
        sbT.append(str);
        return AbstractC0147y.g(sbT, ", errorCode=", str2, ")");
    }
}
