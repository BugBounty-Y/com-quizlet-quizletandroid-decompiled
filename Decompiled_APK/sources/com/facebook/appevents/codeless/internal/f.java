package com.facebook.appevents.codeless.internal;

import android.widget.TextView;
import kotlin.text.Regex;

/* loaded from: classes.dex */
public final class f {
    public static final f a = new f();

    /* JADX WARN: Removed duplicated region for block: B:24:0x0047  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x005a A[Catch: all -> 0x00c5, TRY_LEAVE, TryCatch #1 {all -> 0x00c5, blocks: (B:5:0x000b, B:8:0x0011, B:20:0x0035, B:22:0x003e, B:32:0x005a, B:42:0x0076, B:52:0x0091, B:66:0x00be, B:50:0x008b, B:40:0x0070, B:30:0x0054, B:18:0x002f, B:25:0x0049, B:45:0x0081, B:55:0x009b, B:58:0x00a5, B:60:0x00ab, B:63:0x00b2, B:12:0x001d, B:15:0x0027, B:35:0x0065), top: B:78:0x000b, inners: #0, #2, #3, #4, #5 }] */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0063  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0076 A[Catch: all -> 0x00c5, TRY_LEAVE, TryCatch #1 {all -> 0x00c5, blocks: (B:5:0x000b, B:8:0x0011, B:20:0x0035, B:22:0x003e, B:32:0x005a, B:42:0x0076, B:52:0x0091, B:66:0x00be, B:50:0x008b, B:40:0x0070, B:30:0x0054, B:18:0x002f, B:25:0x0049, B:45:0x0081, B:55:0x009b, B:58:0x00a5, B:60:0x00ab, B:63:0x00b2, B:12:0x001d, B:15:0x0027, B:35:0x0065), top: B:78:0x000b, inners: #0, #2, #3, #4, #5 }] */
    /* JADX WARN: Removed duplicated region for block: B:44:0x007f  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x0091 A[Catch: all -> 0x00c5, TRY_LEAVE, TryCatch #1 {all -> 0x00c5, blocks: (B:5:0x000b, B:8:0x0011, B:20:0x0035, B:22:0x003e, B:32:0x005a, B:42:0x0076, B:52:0x0091, B:66:0x00be, B:50:0x008b, B:40:0x0070, B:30:0x0054, B:18:0x002f, B:25:0x0049, B:45:0x0081, B:55:0x009b, B:58:0x00a5, B:60:0x00ab, B:63:0x00b2, B:12:0x001d, B:15:0x0027, B:35:0x0065), top: B:78:0x000b, inners: #0, #2, #3, #4, #5 }] */
    /* JADX WARN: Removed duplicated region for block: B:54:0x0099  */
    /* JADX WARN: Removed duplicated region for block: B:88:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final boolean b(android.view.View r7) {
        /*
            Method dump skipped, instructions count: 205
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.codeless.internal.f.b(android.view.View):boolean");
    }

    public final boolean a(TextView textView) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return false;
        }
        try {
            String strReplace = new Regex("\\s").replace(g.i(textView), "");
            int length = strReplace.length();
            if (length >= 12 && length <= 19) {
                int i = 0;
                boolean z = false;
                for (int i2 = length - 1; -1 < i2; i2--) {
                    char cCharAt = strReplace.charAt(i2);
                    if (!Character.isDigit(cCharAt)) {
                        return false;
                    }
                    int iDigit = Character.digit((int) cCharAt, 10);
                    if (iDigit < 0) {
                        throw new IllegalArgumentException("Char " + cCharAt + " is not a decimal digit");
                    }
                    if (z && (iDigit = iDigit * 2) > 9) {
                        iDigit = (iDigit % 10) + 1;
                    }
                    i += iDigit;
                    z = !z;
                }
                if (i % 10 == 0) {
                    return true;
                }
            }
            return false;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
            return false;
        }
    }
}
