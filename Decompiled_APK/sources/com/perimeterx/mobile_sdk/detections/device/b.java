package com.perimeterx.mobile_sdk.detections.device;

import com.perimeterx.mobile_sdk.configurations.m;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import kotlin.text.StringsKt__StringsKt;

/* loaded from: classes2.dex */
public final class b {
    public final String a;
    public final String b;
    public final String c;

    public b(String uniqueString, String deviceModel) throws NoSuchAlgorithmException {
        Intrinsics.checkNotNullParameter(uniqueString, "uniqueString");
        Intrinsics.checkNotNullParameter(deviceModel, "deviceModel");
        this.a = uniqueString;
        String upperCase = ((String) StringsKt__StringsKt.split$default(uniqueString, new String[]{"-"}, false, 0, 6, null).get(0)).toUpperCase(Locale.ROOT);
        Intrinsics.checkNotNullExpressionValue(upperCase, "toUpperCase(...)");
        String strValueOf = String.valueOf(upperCase);
        this.b = strValueOf;
        String input = deviceModel + uniqueString + strValueOf;
        Intrinsics.checkNotNullParameter(input, "input");
        m[] mVarArr = m.a;
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
        byte[] bytes = input.getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(bytes, "getBytes(...)");
        byte[] bArrDigest = messageDigest.digest(bytes);
        StringBuilder sb = new StringBuilder(bArrDigest.length * 2);
        for (byte b : bArrDigest) {
            sb.append("0123456789abcdef".charAt((b >> 4) & 15));
            sb.append("0123456789abcdef".charAt(b & 15));
        }
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        String upperCase2 = string.toUpperCase(Locale.ROOT);
        Intrinsics.checkNotNullExpressionValue(upperCase2, "toUpperCase(...)");
        this.c = upperCase2;
    }
}
