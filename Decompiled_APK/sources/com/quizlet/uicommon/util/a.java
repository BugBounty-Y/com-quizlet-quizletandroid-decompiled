package com.quizlet.uicommon.util;

import java.util.regex.Pattern;

/* loaded from: classes3.dex */
public abstract class a {
    public static final Pattern a = Pattern.compile("%([0-9]+\\$|<?)([^a-zA-z%]*)([[a-zA-Z%]&&[^tT]]|[tT][a-zA-Z])");

    /* JADX WARN: Removed duplicated region for block: B:28:0x0083  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static android.text.SpannedString a(java.lang.CharSequence r11, java.lang.Object... r12) {
        /*
            java.util.Locale r0 = java.util.Locale.getDefault()
            android.text.SpannableStringBuilder r1 = new android.text.SpannableStringBuilder
            r1.<init>(r11)
            r11 = 0
            r2 = -1
            r3 = r11
        Lc:
            int r4 = r1.length()
            if (r3 >= r4) goto L9a
            java.util.regex.Pattern r4 = com.quizlet.uicommon.util.a.a
            java.util.regex.Matcher r4 = r4.matcher(r1)
            boolean r3 = r4.find(r3)
            if (r3 != 0) goto L20
            goto L9a
        L20:
            int r3 = r4.start()
            int r5 = r4.end()
            r6 = 1
            java.lang.String r7 = r4.group(r6)
            r8 = 2
            java.lang.String r8 = r4.group(r8)
            r9 = 3
            java.lang.String r4 = r4.group(r9)
            java.lang.String r9 = "%"
            boolean r10 = r9.equals(r4)
            if (r10 == 0) goto L40
            goto L90
        L40:
            java.lang.String r10 = "n"
            boolean r10 = r10.equals(r4)
            if (r10 == 0) goto L4b
            java.lang.String r9 = "\n"
            goto L90
        L4b:
            java.lang.String r10 = ""
            boolean r10 = r10.equals(r7)
            if (r10 == 0) goto L57
            int r2 = r2 + 1
        L55:
            r6 = r2
            goto L70
        L57:
            java.lang.String r10 = "<"
            boolean r10 = r10.equals(r7)
            if (r10 == 0) goto L60
            goto L55
        L60:
            int r10 = r7.length()
            int r10 = r10 - r6
            java.lang.String r7 = r7.substring(r11, r10)
            int r7 = java.lang.Integer.parseInt(r7)
            int r7 = r7 - r6
            r6 = r2
            r2 = r7
        L70:
            r2 = r12[r2]
            java.lang.String r7 = "s"
            boolean r7 = r7.equals(r4)
            if (r7 == 0) goto L83
            boolean r7 = r2 instanceof android.text.Spanned
            if (r7 == 0) goto L83
            r9 = r2
            android.text.Spanned r9 = (android.text.Spanned) r9
        L81:
            r2 = r6
            goto L90
        L83:
            java.lang.String r4 = android.support.v4.media.session.a.B(r9, r8, r4)
            java.lang.Object[] r2 = new java.lang.Object[]{r2}
            java.lang.String r9 = java.lang.String.format(r0, r4, r2)
            goto L81
        L90:
            r1.replace(r3, r5, r9)
            int r4 = r9.length()
            int r3 = r3 + r4
            goto Lc
        L9a:
            android.text.SpannedString r11 = new android.text.SpannedString
            r11.<init>(r1)
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.uicommon.util.a.a(java.lang.CharSequence, java.lang.Object[]):android.text.SpannedString");
    }
}
