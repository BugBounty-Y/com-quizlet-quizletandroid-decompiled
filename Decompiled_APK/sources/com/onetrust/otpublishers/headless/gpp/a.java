package com.onetrust.otpublishers.headless.gpp;

import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import java.util.regex.Pattern;

/* loaded from: classes2.dex */
public abstract class a {
    public static final Pattern a = Pattern.compile("^[0-1]*$", 2);

    public static String a(String str) {
        if (!a.matcher(str).matches()) {
            OTLogger.c("GPPBase64UrlEncoder", 6, "Base64Url encoding failed");
        }
        while (str.length() % 6 > 0) {
            str = str.concat("0");
        }
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (i <= str.length() - 6) {
            int i2 = i + 6;
            String strSubstring = str.substring(i, i2);
            try {
                if (!e.a.matcher(strSubstring).matches()) {
                    OTLogger.c("GPPIntegerEncoder", 6, "Integer decode failed");
                }
                int i3 = 0;
                int i4 = 0;
                while (i3 < strSubstring.length()) {
                    int i5 = i3 + 1;
                    if (strSubstring.charAt(strSubstring.length() - i5) == '1') {
                        i4 += 1 << i3;
                    }
                    i3 = i5;
                }
                sb.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".charAt(i4));
                i = i2;
            } catch (Exception unused) {
                OTLogger.c("GPPBase64UrlEncoder", 6, "Base64Url encoding failed");
            }
        }
        return sb.toString();
    }
}
