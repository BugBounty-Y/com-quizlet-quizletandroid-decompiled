package com.appsflyer.internal;

import androidx.compose.animation.d0;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import kotlin.text.MatchGroup;
import kotlin.text.Regex;
import kotlin.text.StringsKt;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class AFj1aSDK {
    public static final String getMonetizationNetwork(String str, String str2) throws NoSuchAlgorithmException {
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

    public static final int getMonetizationNetwork(@NotNull String str) {
        String str2;
        Integer intOrNull;
        String str3;
        Integer intOrNull2;
        String str4;
        Integer intOrNull3;
        Intrinsics.checkNotNullParameter(str, "");
        kotlin.text.m mVarD = new Regex("(\\d+).(\\d+).(\\d+).*").d(str);
        if (mVarD == null) {
            return -1;
        }
        androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.m mVar = mVarD.c;
        MatchGroup matchGroupB = mVar.b(1);
        int iIntValue = 0;
        int iIntValue2 = ((matchGroupB == null || (str4 = matchGroupB.a) == null || (intOrNull3 = StringsKt.toIntOrNull(str4)) == null) ? 0 : intOrNull3.intValue()) * 1000000;
        MatchGroup matchGroupB2 = mVar.b(2);
        int iIntValue3 = (((matchGroupB2 == null || (str3 = matchGroupB2.a) == null || (intOrNull2 = StringsKt.toIntOrNull(str3)) == null) ? 0 : intOrNull2.intValue()) * 1000) + iIntValue2;
        MatchGroup matchGroupB3 = mVar.b(3);
        if (matchGroupB3 != null && (str2 = matchGroupB3.a) != null && (intOrNull = StringsKt.toIntOrNull(str2)) != null) {
            iIntValue = intOrNull.intValue();
        }
        return iIntValue3 + iIntValue;
    }
}
