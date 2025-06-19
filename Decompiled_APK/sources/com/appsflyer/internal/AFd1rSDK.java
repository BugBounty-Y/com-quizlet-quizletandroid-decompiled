package com.appsflyer.internal;

import androidx.compose.animation.d0;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import kotlin.Pair;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import kotlin.text.MatchGroup;
import kotlin.text.Regex;
import kotlin.text.StringsKt;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class AFd1rSDK {
    @NotNull
    public static final String AFAdRevenueData(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "");
        return "[Exception Manager]: " + str;
    }

    public static final String getCurrencyIso4217Code(String str, String str2) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance(str2);
        byte[] bytes = str.getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(bytes, "");
        byte[] bArrDigest = messageDigest.digest(bytes);
        Intrinsics.checkNotNullExpressionValue(bArrDigest, "");
        String strK = "";
        for (byte b : bArrDigest) {
            strK = android.support.v4.media.session.a.k(strK, d0.s(new Object[]{Byte.valueOf(b)}, 1, "%02x", ""));
        }
        return strK;
    }

    public static final Pair<Integer, Integer> getMediationNetwork(@NotNull String str) {
        String str2;
        String str3;
        String str4;
        Intrinsics.checkNotNullParameter(str, "");
        kotlin.text.m mVarD = new Regex("^(\\d+).(\\+)$|^(\\d+).(\\d+).(\\+)$").d(str);
        if (mVarD != null) {
            androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.m mVar = mVarD.c;
            MatchGroup matchGroupB = mVar.b(1);
            Integer intOrNull = (matchGroupB == null || (str4 = matchGroupB.a) == null) ? null : StringsKt.toIntOrNull(str4);
            MatchGroup matchGroupB2 = mVar.b(3);
            Integer intOrNull2 = (matchGroupB2 == null || (str3 = matchGroupB2.a) == null) ? null : StringsKt.toIntOrNull(str3);
            MatchGroup matchGroupB3 = mVar.b(4);
            Integer intOrNull3 = (matchGroupB3 == null || (str2 = matchGroupB3.a) == null) ? null : StringsKt.toIntOrNull(str2);
            if (intOrNull != null) {
                return new Pair<>(Integer.valueOf(intOrNull.intValue() * 1000000), Integer.valueOf(((intOrNull.intValue() + 1) * 1000000) - 1));
            }
            if (intOrNull2 != null && intOrNull3 != null) {
                return new Pair<>(Integer.valueOf((intOrNull3.intValue() * 1000) + (intOrNull2.intValue() * 1000000)), Integer.valueOf((((intOrNull3.intValue() + 1) * 1000) + (intOrNull2.intValue() * 1000000)) - 1));
            }
        }
        return null;
    }

    public static final Pair<Integer, Integer> getRevenue(@NotNull String str) {
        String str2;
        String str3;
        String str4;
        String str5;
        String str6;
        String str7;
        Intrinsics.checkNotNullParameter(str, "");
        kotlin.text.m mVarD = new Regex("(\\d+).(\\d+).(\\d+)-(\\d+).(\\d+).(\\d+)").d(str);
        if (mVarD != null) {
            androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.m mVar = mVarD.c;
            MatchGroup matchGroupB = mVar.b(1);
            Integer intOrNull = (matchGroupB == null || (str7 = matchGroupB.a) == null) ? null : StringsKt.toIntOrNull(str7);
            MatchGroup matchGroupB2 = mVar.b(2);
            Integer intOrNull2 = (matchGroupB2 == null || (str6 = matchGroupB2.a) == null) ? null : StringsKt.toIntOrNull(str6);
            MatchGroup matchGroupB3 = mVar.b(3);
            Integer intOrNull3 = (matchGroupB3 == null || (str5 = matchGroupB3.a) == null) ? null : StringsKt.toIntOrNull(str5);
            MatchGroup matchGroupB4 = mVar.b(4);
            Integer intOrNull4 = (matchGroupB4 == null || (str4 = matchGroupB4.a) == null) ? null : StringsKt.toIntOrNull(str4);
            MatchGroup matchGroupB5 = mVar.b(5);
            Integer intOrNull5 = (matchGroupB5 == null || (str3 = matchGroupB5.a) == null) ? null : StringsKt.toIntOrNull(str3);
            MatchGroup matchGroupB6 = mVar.b(6);
            Integer intOrNull6 = (matchGroupB6 == null || (str2 = matchGroupB6.a) == null) ? null : StringsKt.toIntOrNull(str2);
            Integer num = intOrNull6;
            if (getRevenue(intOrNull, intOrNull2, intOrNull3, intOrNull4, intOrNull5, intOrNull6)) {
                Intrinsics.d(intOrNull);
                int iIntValue = intOrNull.intValue() * 1000000;
                Intrinsics.d(intOrNull2);
                int iIntValue2 = (intOrNull2.intValue() * 1000) + iIntValue;
                Intrinsics.d(intOrNull3);
                Integer numValueOf = Integer.valueOf(intOrNull3.intValue() + iIntValue2);
                Intrinsics.d(intOrNull4);
                int iIntValue3 = intOrNull4.intValue() * 1000000;
                Intrinsics.d(intOrNull5);
                int iIntValue4 = (intOrNull5.intValue() * 1000) + iIntValue3;
                Intrinsics.d(num);
                return new Pair<>(numValueOf, Integer.valueOf(num.intValue() + iIntValue4));
            }
        }
        return null;
    }

    private static boolean getRevenue(@NotNull Object... objArr) {
        Intrinsics.checkNotNullParameter(objArr, "");
        return !C4933y.u(null, objArr);
    }
}
