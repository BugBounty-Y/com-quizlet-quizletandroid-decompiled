package com.google.android.gms.internal.ads;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* renamed from: com.google.android.gms.internal.ads.b0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1860b0 {
    public static final Pattern c = Pattern.compile("^ [0-9a-fA-F]{8} ([0-9a-fA-F]{8}) ([0-9a-fA-F]{8})");
    public int a = -1;
    public int b = -1;

    public final void a(K4 k4) {
        int i = 0;
        while (true) {
            InterfaceC2856y4[] interfaceC2856y4Arr = k4.a;
            if (i >= interfaceC2856y4Arr.length) {
                return;
            }
            InterfaceC2856y4 interfaceC2856y4 = interfaceC2856y4Arr[i];
            if (interfaceC2856y4 instanceof T0) {
                T0 t0 = (T0) interfaceC2856y4;
                if ("iTunSMPB".equals(t0.c) && b(t0.d)) {
                    return;
                }
            } else if (interfaceC2856y4 instanceof Y0) {
                Y0 y0 = (Y0) interfaceC2856y4;
                if ("com.apple.iTunes".equals(y0.b) && "iTunSMPB".equals(y0.c) && b(y0.d)) {
                    return;
                }
            } else {
                continue;
            }
            i++;
        }
    }

    public final boolean b(String str) throws NumberFormatException {
        Matcher matcher = c.matcher(str);
        if (!matcher.find()) {
            return false;
        }
        try {
            String strGroup = matcher.group(1);
            String str2 = Yo.a;
            int i = Integer.parseInt(strGroup, 16);
            int i2 = Integer.parseInt(matcher.group(2), 16);
            if (i <= 0 && i2 <= 0) {
                return false;
            }
            this.a = i;
            this.b = i2;
            return true;
        } catch (NumberFormatException unused) {
            return false;
        }
    }
}
