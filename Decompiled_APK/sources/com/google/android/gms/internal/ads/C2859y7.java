package com.google.android.gms.internal.ads;

import android.text.TextUtils;

/* renamed from: com.google.android.gms.internal.ads.y7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2859y7 {
    public static final C2859y7 b = new C2859y7(0);
    public static final C2859y7 c = new C2859y7(1);
    public static final C2859y7 d = new C2859y7(2);
    public final /* synthetic */ int a;

    public /* synthetic */ C2859y7(int i) {
        this.a = i;
    }

    public static final String b(String str) {
        if (TextUtils.isEmpty(str)) {
            return str;
        }
        int length = str.length();
        int i = 0;
        int i2 = 0;
        while (i2 < str.length() && str.charAt(i2) == ',') {
            i2++;
        }
        while (length > 0) {
            int i3 = length - 1;
            if (str.charAt(i3) != ',') {
                break;
            }
            length = i3;
        }
        if (length < i2) {
            return null;
        }
        if (i2 != 0) {
            i = i2;
        } else if (length == str.length()) {
            return str;
        }
        return str.substring(i, length);
    }

    public final String a(String str, String str2) {
        switch (this.a) {
            case 0:
                return str2;
            case 1:
                return str != null ? str : str2;
            default:
                String strB = b(str);
                String strB2 = b(str2);
                return TextUtils.isEmpty(strB) ? strB2 : TextUtils.isEmpty(strB2) ? strB : android.support.v4.media.session.a.l(strB, ",", strB2);
        }
    }
}
