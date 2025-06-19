package com.appsflyer.internal;

import android.content.Context;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public interface AFb1bSDK {

    @NotNull
    public static final AFa1vSDK AFa1vSDK = AFa1vSDK.AFAdRevenueData;

    public static final class AFa1vSDK {
        static final /* synthetic */ AFa1vSDK AFAdRevenueData = new AFa1vSDK();
        private static long getRevenue = 500;

        private AFa1vSDK() {
        }

        public static long getRevenue() {
            return getRevenue;
        }
    }

    public interface AFa1zSDK {
        void getCurrencyIso4217Code();

        void getRevenue(@NotNull AFh1qSDK aFh1qSDK);
    }

    void AFAdRevenueData();

    void AFAdRevenueData(@NotNull Context context, @NotNull AFa1zSDK aFa1zSDK);

    boolean getCurrencyIso4217Code();
}
