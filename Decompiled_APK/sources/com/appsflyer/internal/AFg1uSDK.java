package com.appsflyer.internal;

import android.content.Context;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public interface AFg1uSDK {

    public static final class AFa1uSDK {
        final String getMediationNetwork;
        final float getRevenue;

        public AFa1uSDK(float f, String str) {
            this.getRevenue = f;
            this.getMediationNetwork = str;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof AFa1uSDK)) {
                return false;
            }
            AFa1uSDK aFa1uSDK = (AFa1uSDK) obj;
            return Float.compare(this.getRevenue, aFa1uSDK.getRevenue) == 0 && Intrinsics.b(this.getMediationNetwork, aFa1uSDK.getMediationNetwork);
        }

        public final int hashCode() {
            int iHashCode = Float.hashCode(this.getRevenue) * 31;
            String str = this.getMediationNetwork;
            return iHashCode + (str == null ? 0 : str.hashCode());
        }

        @NotNull
        public final String toString() {
            return "BatteryData(level=" + this.getRevenue + ", charging=" + this.getMediationNetwork + ")";
        }
    }

    @NotNull
    AFa1uSDK getRevenue(@NotNull Context context);
}
