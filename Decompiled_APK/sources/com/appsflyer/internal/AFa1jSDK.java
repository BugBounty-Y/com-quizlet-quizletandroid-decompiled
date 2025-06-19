package com.appsflyer.internal;

import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class AFa1jSDK {

    @NotNull
    public static final AFa1ySDK AFa1ySDK = new AFa1ySDK(null);

    @NotNull
    final Map<String, Object> getMediationNetwork;
    final AFa1gSDK getMonetizationNetwork;

    @Metadata
    public static final class AFa1ySDK {
        private AFa1ySDK() {
        }

        /* JADX WARN: Multi-variable type inference failed */
        @NotNull
        public static AFa1jSDK AFAdRevenueData(@NotNull AFh1rSDK aFh1rSDK) {
            Intrinsics.checkNotNullParameter(aFh1rSDK, "");
            Map<String, Object> map = aFh1rSDK.AFAdRevenueData;
            Intrinsics.checkNotNullExpressionValue(map, "");
            return new AFa1jSDK(map, null, 2, 0 == true ? 1 : 0);
        }

        @NotNull
        public static AFa1jSDK getMonetizationNetwork(@NotNull AFa1gSDK aFa1gSDK) {
            Intrinsics.checkNotNullParameter(aFa1gSDK, "");
            return new AFa1jSDK(new LinkedHashMap(), aFa1gSDK, null);
        }

        public /* synthetic */ AFa1ySDK(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    private AFa1jSDK(Map<String, Object> map, AFa1gSDK aFa1gSDK) {
        this.getMediationNetwork = map;
        this.getMonetizationNetwork = aFa1gSDK;
    }

    @NotNull
    public static final AFa1jSDK AFAdRevenueData(@NotNull AFh1rSDK aFh1rSDK) {
        return AFa1ySDK.AFAdRevenueData(aFh1rSDK);
    }

    public final void getCurrencyIso4217Code(@NotNull String str, Object obj) {
        Intrinsics.checkNotNullParameter(str, "");
        this.getMediationNetwork.put(str, obj);
        AFa1gSDK aFa1gSDK = this.getMonetizationNetwork;
        if (aFa1gSDK != null) {
            aFa1gSDK.getMediationNetwork(this.getMediationNetwork);
        }
    }

    public final boolean getCurrencyIso4217Code(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "");
        return this.getMediationNetwork.containsKey(str);
    }

    public /* synthetic */ AFa1jSDK(Map map, AFa1gSDK aFa1gSDK, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(map, (i & 2) != 0 ? null : aFa1gSDK);
    }

    @NotNull
    public static final AFa1jSDK getCurrencyIso4217Code(@NotNull AFa1gSDK aFa1gSDK) {
        return AFa1ySDK.getMonetizationNetwork(aFa1gSDK);
    }

    public /* synthetic */ AFa1jSDK(Map map, AFa1gSDK aFa1gSDK, DefaultConstructorMarker defaultConstructorMarker) {
        this(map, aFa1gSDK);
    }
}
