package com.appsflyer.internal;

import android.util.Base64;
import com.appsflyer.AFLogger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.B;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;
import kotlin.text.Charsets;
import kotlin.text.Regex;
import kotlin.text.StringsKt;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class AFe1zSDK {
    private static AFe1vSDK component3;

    @NotNull
    public final kotlin.k AFAdRevenueData;

    @NotNull
    private final kotlin.k areAllFieldsValid;

    @NotNull
    private final AFc1pSDK getCurrencyIso4217Code;

    @NotNull
    private final AFc1qSDK getMonetizationNetwork;

    @NotNull
    public static final AFa1ySDK AFa1ySDK = new AFa1ySDK(null);

    @NotNull
    public static String getMediationNetwork = "https://%scdn-%ssettings.%s/android/v1/%s/settings";

    @NotNull
    public static String getRevenue = "https://%scdn-%stestsettings.%s/android/v1/%s/settings";

    @NotNull
    private static final List<String> component1 = B.j("googleplay", "playstore", "googleplaystore");

    @Metadata
    /* renamed from: com.appsflyer.internal.AFe1zSDK$4, reason: invalid class name */
    public static final class AnonymousClass4 extends r implements Function0<String> {
        public AnonymousClass4() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        /* renamed from: getMediationNetwork, reason: merged with bridge method [inline-methods] */
        public final String invoke() {
            String packageName = AFe1zSDK.this.getCurrencyIso4217Code.getRevenue.getMonetizationNetwork.getPackageName();
            Intrinsics.checkNotNullExpressionValue(packageName, "");
            return AFe1zSDK.getMonetizationNetwork(packageName, AFe1zSDK.getCurrencyIso4217Code(AFe1zSDK.this));
        }
    }

    @Metadata
    /* renamed from: com.appsflyer.internal.AFe1zSDK$5, reason: invalid class name */
    public static final class AnonymousClass5 extends r implements Function0<String> {
        public AnonymousClass5() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        /* renamed from: AFAdRevenueData, reason: merged with bridge method [inline-methods] */
        public final String invoke() {
            String monetizationNetwork = AFa1tSDK.getMonetizationNetwork(AFe1zSDK.this.getMonetizationNetwork, AFe1zSDK.this.getCurrencyIso4217Code.component2());
            if (monetizationNetwork != null && !StringsKt.O(monetizationNetwork)) {
                String string = StringsKt.g0(monetizationNetwork).toString();
                List<String> revenue = AFa1ySDK.getRevenue();
                Locale locale = Locale.getDefault();
                Intrinsics.checkNotNullExpressionValue(locale, "");
                String lowerCase = string.toLowerCase(locale);
                Intrinsics.checkNotNullExpressionValue(lowerCase, "");
                if (revenue.contains(lowerCase)) {
                    String str = String.format("AF detected using redundant Google-Play channel for attribution - %s. Using without channel postfix.", Arrays.copyOf(new Object[]{string}, 1));
                    Intrinsics.checkNotNullExpressionValue(str, "");
                    AFLogger.afWarnLog(str);
                    monetizationNetwork = "";
                } else {
                    monetizationNetwork = "-".concat(string);
                }
            }
            return StringsKt.g0(monetizationNetwork != null ? monetizationNetwork : "").toString();
        }
    }

    public /* synthetic */ class AFa1uSDK {
        public static final /* synthetic */ int[] getCurrencyIso4217Code;

        static {
            int[] iArr = new int[AFe1wSDK.values().length];
            try {
                iArr[AFe1wSDK.DEFAULT.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[AFe1wSDK.API.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                iArr[AFe1wSDK.RC.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            getCurrencyIso4217Code = iArr;
        }
    }

    @Metadata
    public static final class AFa1ySDK {
        private AFa1ySDK() {
        }

        public static void getMediationNetwork(AFe1vSDK aFe1vSDK) {
            AFe1zSDK.component3 = aFe1vSDK;
        }

        @NotNull
        public static List<String> getRevenue() {
            return AFe1zSDK.component1;
        }

        public /* synthetic */ AFa1ySDK(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public AFe1zSDK(@NotNull AFc1pSDK aFc1pSDK, @NotNull AFc1qSDK aFc1qSDK) {
        Intrinsics.checkNotNullParameter(aFc1pSDK, "");
        Intrinsics.checkNotNullParameter(aFc1qSDK, "");
        this.getCurrencyIso4217Code = aFc1pSDK;
        this.getMonetizationNetwork = aFc1qSDK;
        this.areAllFieldsValid = kotlin.l.b(new AnonymousClass5());
        this.AFAdRevenueData = kotlin.l.b(new AnonymousClass4());
    }

    public static boolean AFAdRevenueData() {
        return component3 == null;
    }

    public static final /* synthetic */ String getMonetizationNetwork(String str, String str2) throws NoSuchAlgorithmException {
        String str3 = str + str2;
        Intrinsics.checkNotNullParameter(str3, "");
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] bytes = str3.getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(bytes, "");
        byte[] bArrDigest = messageDigest.digest(bytes);
        Intrinsics.checkNotNullExpressionValue(bArrDigest, "");
        String strEncodeToString = Base64.encodeToString(bArrDigest, 2);
        Intrinsics.checkNotNullExpressionValue(strEncodeToString, "");
        String lowerCase = strEncodeToString.toLowerCase(Locale.ROOT);
        Intrinsics.checkNotNullExpressionValue(lowerCase, "");
        String strSubstring = new Regex("[^\\w]+").replace(lowerCase, "").substring(0, 6);
        Intrinsics.checkNotNullExpressionValue(strSubstring, "");
        return strSubstring + ".";
    }

    @NotNull
    public final String getCurrencyIso4217Code() {
        int i = AFa1uSDK.getCurrencyIso4217Code[(AFAdRevenueData() ? AFe1wSDK.DEFAULT : AFe1wSDK.API).ordinal()];
        if (i == 1) {
            return (String) this.AFAdRevenueData.getValue();
        }
        if (i != 2) {
            if (i == 3) {
                return "";
            }
            throw new NoWhenBranchMatchedException();
        }
        AFe1vSDK aFe1vSDK = component3;
        String str = aFe1vSDK != null ? aFe1vSDK.AFAdRevenueData : null;
        return str == null ? "" : str;
    }

    @NotNull
    public final String getMediationNetwork() {
        int i = AFa1uSDK.getCurrencyIso4217Code[(AFAdRevenueData() ? AFe1wSDK.DEFAULT : AFe1wSDK.API).ordinal()];
        if (i == 1) {
            return "appsflyersdk.com";
        }
        if (i != 2) {
            if (i == 3) {
                return "";
            }
            throw new NoWhenBranchMatchedException();
        }
        AFe1vSDK aFe1vSDK = component3;
        String str = aFe1vSDK != null ? aFe1vSDK.getMediationNetwork : null;
        return str == null ? "" : str;
    }

    public static final /* synthetic */ String getCurrencyIso4217Code(AFe1zSDK aFe1zSDK) {
        return (String) aFe1zSDK.areAllFieldsValid.getValue();
    }

    public static final void getMediationNetwork(AFe1vSDK aFe1vSDK) {
        AFa1ySDK.getMediationNetwork(aFe1vSDK);
    }
}
