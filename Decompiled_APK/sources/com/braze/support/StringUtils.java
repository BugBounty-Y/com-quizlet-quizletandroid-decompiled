package com.braze.support;

import android.content.Context;
import android.content.SharedPreferences;
import com.braze.AbstractC1484j;
import com.braze.C1481g;
import com.braze.support.BrazeLogger;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Locale;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import kotlin.text.StringsKt;

@Metadata
/* loaded from: classes.dex */
public abstract class StringUtils {
    private static final String TAG = BrazeLogger.INSTANCE.getBrazeLogTag("StringUtils");

    public static final long getByteSize(String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullExpressionValue(str.getBytes(Charsets.UTF_8), "getBytes(...)");
        return r2.length;
    }

    public static final String getCacheFileSuffix(Context context, String str) {
        Intrinsics.checkNotNullParameter(context, "context");
        return getCacheFileSuffix(context, str, null);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getCacheFileSuffix$lambda$1() {
        return "The saved user id hash was null or empty.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getCacheFileSuffix$lambda$2(String str, String str2) {
        return android.support.v4.media.session.a.m("Generating MD5 for user id: ", str, " apiKey: ", str2);
    }

    public static final String getMd5Hash(String str) throws NoSuchAlgorithmException {
        Intrinsics.checkNotNullParameter(str, "<this>");
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        byte[] bytes = str.getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(bytes, "getBytes(...)");
        String str2 = String.format(Locale.US, "%032x", Arrays.copyOf(new Object[]{new BigInteger(1, messageDigest.digest(bytes))}, 1));
        Intrinsics.checkNotNullExpressionValue(str2, "format(...)");
        return str2;
    }

    private static final String getSuffixFromUserIdHashAndApiKey(String str, String str2) {
        if (str2 == null || StringsKt.O(str2)) {
            return AbstractC1484j.a(".", str);
        }
        return "." + str + '.' + str2;
    }

    public static final void ifNonEmpty(String str, Function1<? super String, Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        if (str == null || str.length() == 0) {
            return;
        }
        block.invoke(str);
    }

    public static final boolean isNullOrBlank(String str) {
        return str == null || StringsKt.O(str);
    }

    public static final String truncateToByteLength(String str, int i) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        if (getByteSize(str) <= i) {
            return str;
        }
        StringBuilder sb = new StringBuilder();
        char[] charArray = str.toCharArray();
        Intrinsics.checkNotNullExpressionValue(charArray, "toCharArray(...)");
        int byteSize = 0;
        for (char c : charArray) {
            byteSize += (int) getByteSize(String.valueOf(c));
            if (byteSize > i) {
                break;
            }
            sb.append(c);
        }
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }

    public static final String getCacheFileSuffix(Context context, String str, String str2) throws NoSuchAlgorithmException {
        Intrinsics.checkNotNullParameter(context, "context");
        String str3 = str == null ? "null" : str;
        if (str3.equals("null")) {
            return getSuffixFromUserIdHashAndApiKey("37a6259cc0c1dae299a7866489dff0bd", str2);
        }
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.appboy.support.stringutils.cachefilesuffix", 0);
        String string = sharedPreferences.getString("user_id_key", null);
        if (string != null && string.equals(str3)) {
            String string2 = sharedPreferences.getString("user_id_hash_value", null);
            if (string2 != null && string2.length() != 0) {
                return getSuffixFromUserIdHashAndApiKey(string2, str2);
            }
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new v(4), 14, (Object) null);
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new C1481g(24, str3, str2), 12, (Object) null);
        String md5Hash = getMd5Hash(str3);
        sharedPreferences.edit().putString("user_id_key", str3).putString("user_id_hash_value", md5Hash).apply();
        return getSuffixFromUserIdHashAndApiKey(md5Hash, str2);
    }
}
