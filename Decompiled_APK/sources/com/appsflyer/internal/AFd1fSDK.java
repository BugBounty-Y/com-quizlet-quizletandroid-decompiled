package com.appsflyer.internal;

import android.text.TextUtils;
import com.appsflyer.AppsFlyerLib;
import com.pubmatic.sdk.video.c;
import java.util.Map;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.collections.V;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class AFd1fSDK extends AFd1cSDK {

    @NotNull
    public static final AFa1tSDK AFa1tSDK = new AFa1tSDK(null);

    @Metadata
    public static final class AFa1tSDK {
        private AFa1tSDK() {
        }

        public static String getCurrencyIso4217Code(String str, String str2, String str3) {
            return String.format(AFd1oSDK.AFAdRevenueData, AppsFlyerLib.getInstance().getHostPrefix(), ((com.appsflyer.internal.AFa1tSDK) com.appsflyer.internal.AFa1tSDK.getMonetizationNetwork(new Object[0], -631580017, 631580017, (int) System.currentTimeMillis())).getHostName()) + str + str3 + "?device_id=" + str2;
        }

        public static String getRevenue(@NotNull String str, @NotNull String str2, String str3, @NotNull String str4, @NotNull String str5) {
            Intrinsics.checkNotNullParameter(str, "");
            Intrinsics.checkNotNullParameter(str2, "");
            Intrinsics.checkNotNullParameter(str4, "");
            Intrinsics.checkNotNullParameter(str5, "");
            return AFj1cSDK.getRevenue(TextUtils.join("\u2063", new String[]{str5, str3, str + str2}), str4);
        }

        public /* synthetic */ AFa1tSDK(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public /* synthetic */ AFd1fSDK(String str, Map map, byte[] bArr, String str2, boolean z, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, map, (i & 4) != 0 ? null : bArr, (i & 8) != 0 ? "GET" : str2, (i & 16) != 0 ? false : z);
    }

    @NotNull
    public static final AFd1fSDK getMonetizationNetwork(@NotNull String str, String str2, @NotNull String str3, @NotNull String str4) {
        Intrinsics.checkNotNullParameter(str, "");
        Intrinsics.checkNotNullParameter(str3, "");
        Intrinsics.checkNotNullParameter(str4, "");
        String currencyIso4217Code = AFa1tSDK.getCurrencyIso4217Code(str, str2, str3);
        String strValueOf = String.valueOf(System.currentTimeMillis());
        AFd1fSDK aFd1fSDK = new AFd1fSDK(currencyIso4217Code, V.f(new Pair("Connection", "close"), new Pair("af_request_epoch_ms", strValueOf), new Pair("af_sig", AFa1tSDK.getRevenue(str, str3, str2, str4, strValueOf))), null, null, false, 28, null);
        aFd1fSDK.component4 = c.a.DEFAULT_MEDIA_URI_TIMEOUT;
        return aFd1fSDK;
    }

    private AFd1fSDK(String str, Map<String, String> map, byte[] bArr, String str2, boolean z) {
        super(str, bArr, str2, map, z);
    }
}
