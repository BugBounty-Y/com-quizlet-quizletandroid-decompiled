package com.appsflyer.internal;

import androidx.camera.camera2.internal.AbstractC0147y;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class AFe1xSDK {

    @NotNull
    public final AFe1wSDK AFAdRevenueData;

    @NotNull
    public final String getMediationNetwork;
    public final String getRevenue;

    public AFe1xSDK(@NotNull String str, String str2, @NotNull AFe1wSDK aFe1wSDK) {
        Intrinsics.checkNotNullParameter(str, "");
        Intrinsics.checkNotNullParameter(aFe1wSDK, "");
        this.getMediationNetwork = str;
        this.getRevenue = str2;
        this.AFAdRevenueData = aFe1wSDK;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof AFe1xSDK)) {
            return false;
        }
        AFe1xSDK aFe1xSDK = (AFe1xSDK) obj;
        return Intrinsics.b(this.getMediationNetwork, aFe1xSDK.getMediationNetwork) && Intrinsics.b(this.getRevenue, aFe1xSDK.getRevenue) && this.AFAdRevenueData == aFe1xSDK.AFAdRevenueData;
    }

    public final int hashCode() {
        int iHashCode = this.getMediationNetwork.hashCode() * 31;
        String str = this.getRevenue;
        return this.AFAdRevenueData.hashCode() + ((iHashCode + (str == null ? 0 : str.hashCode())) * 31);
    }

    @NotNull
    public final String toString() {
        String str = this.getMediationNetwork;
        String str2 = this.getRevenue;
        AFe1wSDK aFe1wSDK = this.AFAdRevenueData;
        StringBuilder sbH = AbstractC0147y.h("HostMeta(name=", str, ", prefix=", str2, ", method=");
        sbH.append(aFe1wSDK);
        sbH.append(")");
        return sbH.toString();
    }
}
