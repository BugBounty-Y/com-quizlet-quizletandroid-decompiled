package com.appsflyer.internal;

import android.util.Base64;
import androidx.camera.camera2.internal.AbstractC0147y;
import java.nio.charset.Charset;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import kotlin.text.D;
import kotlin.text.StringsKt;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.json.JSONException;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public final class AFc1cSDK {

    @NotNull
    public static final AFa1ySDK AFa1ySDK = new AFa1ySDK(null);

    @NotNull
    public String AFAdRevenueData;
    int getMediationNetwork;

    @NotNull
    final String getMonetizationNetwork;

    @NotNull
    public String getRevenue;

    @Metadata
    public static final class AFa1ySDK {
        private AFa1ySDK() {
        }

        private static boolean getMediationNetwork(Integer num, String... strArr) {
            boolean z = num == null;
            int length = strArr.length;
            for (int i = 0; i < 3; i++) {
                String str = strArr[i];
                z = z || str == null || str.length() == 0;
            }
            return z;
        }

        public static AFc1cSDK getRevenue(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "");
            List<String> listSplit$default = StringsKt__StringsKt.split$default(str, new String[]{"\n"}, false, 0, 6, null);
            if (listSplit$default.size() == 4) {
                String revenue = null;
                String revenue2 = null;
                String revenue3 = null;
                Integer numValueOf = null;
                for (String str2 : listSplit$default) {
                    if (D.r(str2, "label=", false)) {
                        revenue = getRevenue(str2, "label=");
                    } else if (D.r(str2, "hashName=", false)) {
                        revenue2 = getRevenue(str2, "hashName=");
                    } else if (!D.r(str2, "stackTrace=", false)) {
                        if (!D.r(str2, "c=", false)) {
                            break;
                        }
                        String strSubstring = str2.substring(2);
                        Intrinsics.checkNotNullExpressionValue(strSubstring, "");
                        numValueOf = Integer.valueOf(Integer.parseInt(StringsKt.g0(strSubstring).toString()));
                    } else {
                        revenue3 = getRevenue(str2, "stackTrace=");
                    }
                }
                if (!getMediationNetwork(numValueOf, revenue, revenue2, revenue3)) {
                    Intrinsics.d(revenue);
                    Intrinsics.d(revenue2);
                    Intrinsics.d(revenue3);
                    Intrinsics.d(numValueOf);
                    return new AFc1cSDK(revenue, revenue2, revenue3, numValueOf.intValue());
                }
            }
            return null;
        }

        public /* synthetic */ AFa1ySDK(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private static String getRevenue(String str, String str2) {
            String strSubstring = str.substring(str2.length());
            Intrinsics.checkNotNullExpressionValue(strSubstring, "");
            String string = StringsKt.g0(strSubstring).toString();
            Intrinsics.checkNotNullParameter(string, "");
            Charset charset = Charsets.UTF_8;
            byte[] bytes = string.getBytes(charset);
            Intrinsics.checkNotNullExpressionValue(bytes, "");
            Intrinsics.checkNotNullParameter(bytes, "");
            byte[] bArrDecode = Base64.decode(bytes, 2);
            Intrinsics.checkNotNullExpressionValue(bArrDecode, "");
            return new String(bArrDecode, charset);
        }
    }

    public AFc1cSDK(@NotNull String str, @NotNull String str2, @NotNull String str3, int i) {
        Intrinsics.checkNotNullParameter(str, "");
        Intrinsics.checkNotNullParameter(str2, "");
        Intrinsics.checkNotNullParameter(str3, "");
        this.getRevenue = str;
        this.getMonetizationNetwork = str2;
        this.AFAdRevenueData = str3;
        this.getMediationNetwork = i;
    }

    @NotNull
    public final String AFAdRevenueData() {
        String str = this.getRevenue;
        Intrinsics.checkNotNullParameter(str, "");
        Charset charset = Charsets.UTF_8;
        byte[] bytes = str.getBytes(charset);
        Intrinsics.checkNotNullExpressionValue(bytes, "");
        String strEncodeToString = Base64.encodeToString(bytes, 2);
        String str2 = this.getMonetizationNetwork;
        Intrinsics.checkNotNullParameter(str2, "");
        byte[] bytes2 = str2.getBytes(charset);
        Intrinsics.checkNotNullExpressionValue(bytes2, "");
        String strEncodeToString2 = Base64.encodeToString(bytes2, 2);
        String str3 = this.AFAdRevenueData;
        Intrinsics.checkNotNullParameter(str3, "");
        byte[] bytes3 = str3.getBytes(charset);
        Intrinsics.checkNotNullExpressionValue(bytes3, "");
        String strEncodeToString3 = Base64.encodeToString(bytes3, 2);
        int i = this.getMediationNetwork;
        StringBuilder sbH = AbstractC0147y.h("label=", strEncodeToString, "\nhashName=", strEncodeToString2, "\nstackTrace=");
        sbH.append(strEncodeToString3);
        sbH.append("\nc=");
        sbH.append(i);
        return sbH.toString();
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof AFc1cSDK)) {
            return false;
        }
        AFc1cSDK aFc1cSDK = (AFc1cSDK) obj;
        return Intrinsics.b(this.getRevenue, aFc1cSDK.getRevenue) && Intrinsics.b(this.getMonetizationNetwork, aFc1cSDK.getMonetizationNetwork) && Intrinsics.b(this.AFAdRevenueData, aFc1cSDK.AFAdRevenueData) && this.getMediationNetwork == aFc1cSDK.getMediationNetwork;
    }

    @NotNull
    public final JSONObject getRevenue() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("label", this.getRevenue);
        jSONObject.put("hash_name", this.getMonetizationNetwork);
        jSONObject.put("st", this.AFAdRevenueData);
        jSONObject.put("c", String.valueOf(this.getMediationNetwork));
        return jSONObject;
    }

    public final int hashCode() {
        return Integer.hashCode(this.getMediationNetwork) + ((this.AFAdRevenueData.hashCode() + ((this.getMonetizationNetwork.hashCode() + (this.getRevenue.hashCode() * 31)) * 31)) * 31);
    }

    @NotNull
    public final String toString() {
        String str = this.getRevenue;
        String str2 = this.getMonetizationNetwork;
        String str3 = this.AFAdRevenueData;
        int i = this.getMediationNetwork;
        StringBuilder sbH = AbstractC0147y.h("ExceptionInfo(label=", str, ", hashName=", str2, ", stackTrace=");
        sbH.append(str3);
        sbH.append(", counter=");
        sbH.append(i);
        sbH.append(")");
        return sbH.toString();
    }

    public /* synthetic */ AFc1cSDK(String str, String str2, String str3, int i, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, str2, str3, (i2 & 8) != 0 ? 1 : i);
    }
}
