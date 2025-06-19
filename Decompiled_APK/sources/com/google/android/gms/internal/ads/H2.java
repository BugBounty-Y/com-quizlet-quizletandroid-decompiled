package com.google.android.gms.internal.ads;

import android.graphics.Color;
import android.text.TextUtils;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* loaded from: classes2.dex */
public abstract class H2 {
    public static final Pattern a = Pattern.compile("^(\\S+)\\s+-->\\s+(\\S+)(.*)?$");
    public static final Pattern b = Pattern.compile("(\\S+?):(\\S+)");
    public static final Map c;
    public static final Map d;

    static {
        HashMap map = new HashMap();
        map.put("white", Integer.valueOf(Color.rgb(255, 255, 255)));
        map.put("lime", Integer.valueOf(Color.rgb(0, 255, 0)));
        map.put("cyan", Integer.valueOf(Color.rgb(0, 255, 255)));
        map.put("red", Integer.valueOf(Color.rgb(255, 0, 0)));
        map.put("yellow", Integer.valueOf(Color.rgb(255, 255, 0)));
        map.put("magenta", Integer.valueOf(Color.rgb(255, 0, 255)));
        map.put("blue", Integer.valueOf(Color.rgb(0, 0, 255)));
        map.put("black", Integer.valueOf(Color.rgb(0, 0, 0)));
        c = Collections.unmodifiableMap(map);
        HashMap map2 = new HashMap();
        map2.put("bg_white", Integer.valueOf(Color.rgb(255, 255, 255)));
        map2.put("bg_lime", Integer.valueOf(Color.rgb(0, 255, 0)));
        map2.put("bg_cyan", Integer.valueOf(Color.rgb(0, 255, 255)));
        map2.put("bg_red", Integer.valueOf(Color.rgb(255, 0, 0)));
        map2.put("bg_yellow", Integer.valueOf(Color.rgb(255, 255, 0)));
        map2.put("bg_magenta", Integer.valueOf(Color.rgb(255, 0, 255)));
        map2.put("bg_blue", Integer.valueOf(Color.rgb(0, 0, 255)));
        map2.put("bg_black", Integer.valueOf(Color.rgb(0, 0, 0)));
        d = Collections.unmodifiableMap(map2);
    }

    /* JADX WARN: Removed duplicated region for block: B:129:0x0221  */
    /* JADX WARN: Removed duplicated region for block: B:131:0x0224  */
    /* JADX WARN: Removed duplicated region for block: B:141:0x0253  */
    /* JADX WARN: Removed duplicated region for block: B:143:0x0258  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x00a2 A[FALL_THROUGH] */
    /* JADX WARN: Removed duplicated region for block: B:76:0x0136  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x013c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static android.text.SpannedString a(java.lang.String r19, java.lang.String r20, java.util.List r21) {
        /*
            Method dump skipped, instructions count: 638
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.H2.a(java.lang.String, java.lang.String, java.util.List):android.text.SpannedString");
    }

    public static int b(List list, String str, D2 d2) {
        ArrayList arrayListD = d(list, str, d2);
        for (int i = 0; i < arrayListD.size(); i++) {
            int i2 = ((F2) arrayListD.get(i)).b.o;
            if (i2 != -1) {
                return i2;
            }
        }
        return -1;
    }

    public static A2 c(String str, Matcher matcher, Kn kn, ArrayList arrayList) {
        G2 g2 = new G2();
        try {
            String strGroup = matcher.group(1);
            if (strGroup == null) {
                throw null;
            }
            g2.a = AbstractC1795We.k(strGroup);
            String strGroup2 = matcher.group(2);
            if (strGroup2 == null) {
                throw null;
            }
            g2.b = AbstractC1795We.k(strGroup2);
            String strGroup3 = matcher.group(3);
            strGroup3.getClass();
            f(strGroup3, g2);
            StringBuilder sb = new StringBuilder();
            String strL = kn.L(StandardCharsets.UTF_8);
            while (!TextUtils.isEmpty(strL)) {
                if (sb.length() > 0) {
                    sb.append("\n");
                }
                sb.append(strL.trim());
                strL = kn.L(StandardCharsets.UTF_8);
            }
            g2.c = a(str, sb.toString(), arrayList);
            return new A2(g2.a().a(), g2.a, g2.b);
        } catch (IllegalArgumentException unused) {
            AbstractC2096gb.J("WebvttCueParser", "Skipping cue with bad header: ".concat(String.valueOf(matcher.group())));
            return null;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x003d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.util.ArrayList d(java.util.List r8, java.lang.String r9, com.google.android.gms.internal.ads.D2 r10) {
        /*
            java.util.ArrayList r0 = new java.util.ArrayList
            r0.<init>()
            r1 = 0
            r2 = r1
        L7:
            int r3 = r8.size()
            if (r2 >= r3) goto L7a
            java.lang.Object r3 = r8.get(r2)
            com.google.android.gms.internal.ads.z2 r3 = (com.google.android.gms.internal.ads.C2897z2) r3
            java.lang.String r4 = r10.a
            java.lang.String r5 = r3.a
            boolean r5 = r5.isEmpty()
            if (r5 == 0) goto L3f
            java.lang.String r5 = r3.b
            boolean r5 = r5.isEmpty()
            if (r5 == 0) goto L3f
            java.util.Set r5 = r3.c
            boolean r5 = r5.isEmpty()
            if (r5 == 0) goto L3f
            java.lang.String r5 = r3.d
            boolean r5 = r5.isEmpty()
            if (r5 == 0) goto L3f
            boolean r4 = android.text.TextUtils.isEmpty(r4)
            if (r4 == 0) goto L3d
            r4 = 1
            goto L6d
        L3d:
            r4 = r1
            goto L6d
        L3f:
            java.lang.String r5 = r3.a
            r6 = 1073741824(0x40000000, float:2.0)
            int r5 = com.google.android.gms.internal.ads.C2897z2.a(r5, r1, r9, r6)
            java.lang.String r6 = r3.b
            r7 = 2
            int r4 = com.google.android.gms.internal.ads.C2897z2.a(r6, r5, r4, r7)
            java.lang.String r5 = r3.d
            java.lang.String r6 = r10.c
            r7 = 4
            int r4 = com.google.android.gms.internal.ads.C2897z2.a(r5, r4, r6, r7)
            r5 = -1
            if (r4 == r5) goto L3d
            java.util.Set r5 = r3.c
            java.util.Set r6 = r10.d
            boolean r5 = r6.containsAll(r5)
            if (r5 != 0) goto L65
            goto L3d
        L65:
            java.util.Set r5 = r3.c
            int r5 = r5.size()
            int r5 = r5 * r7
            int r4 = r4 + r5
        L6d:
            if (r4 <= 0) goto L77
            com.google.android.gms.internal.ads.F2 r5 = new com.google.android.gms.internal.ads.F2
            r5.<init>(r4, r3)
            r0.add(r5)
        L77:
            int r2 = r2 + 1
            goto L7
        L7a:
            java.util.Collections.sort(r0)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.H2.d(java.util.List, java.lang.String, com.google.android.gms.internal.ads.D2):java.util.ArrayList");
    }

    /* JADX WARN: Removed duplicated region for block: B:43:0x0086  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void e(java.lang.String r18, com.google.android.gms.internal.ads.D2 r19, java.util.List r20, android.text.SpannableStringBuilder r21, java.util.List r22) {
        /*
            Method dump skipped, instructions count: 622
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.H2.e(java.lang.String, com.google.android.gms.internal.ads.D2, java.util.List, android.text.SpannableStringBuilder, java.util.List):void");
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    public static void f(String str, G2 g2) {
        Matcher matcher = b.matcher(str);
        while (matcher.find()) {
            int i = 1;
            String strGroup = matcher.group(1);
            strGroup.getClass();
            int i2 = 2;
            String strGroup2 = matcher.group(2);
            strGroup2.getClass();
            try {
                char c2 = 65535;
                if ("line".equals(strGroup)) {
                    int iIndexOf = strGroup2.indexOf(44);
                    if (iIndexOf != -1) {
                        String strSubstring = strGroup2.substring(iIndexOf + 1);
                        switch (strSubstring.hashCode()) {
                            case -1364013995:
                                if (strSubstring.equals("center")) {
                                    c2 = 1;
                                    break;
                                }
                                break;
                            case -1074341483:
                                if (strSubstring.equals("middle")) {
                                    c2 = 2;
                                    break;
                                }
                                break;
                            case 100571:
                                if (strSubstring.equals("end")) {
                                    c2 = 3;
                                    break;
                                }
                                break;
                            case 109757538:
                                if (strSubstring.equals("start")) {
                                    c2 = 0;
                                    break;
                                }
                                break;
                        }
                        if (c2 == 0) {
                            i2 = 0;
                        } else if (c2 == 1 || c2 == 2) {
                            i2 = 1;
                        } else if (c2 != 3) {
                            AbstractC2096gb.J("WebvttCueParser", "Invalid anchor value: ".concat(strSubstring));
                            i2 = Integer.MIN_VALUE;
                        }
                        g2.g = i2;
                        strGroup2 = strGroup2.substring(0, iIndexOf);
                    }
                    if (strGroup2.endsWith("%")) {
                        g2.e = AbstractC1795We.a(strGroup2);
                        g2.f = 0;
                    } else {
                        g2.e = Integer.parseInt(strGroup2);
                        g2.f = 1;
                    }
                } else if ("align".equals(strGroup)) {
                    switch (strGroup2.hashCode()) {
                        case -1364013995:
                            if (strGroup2.equals("center")) {
                                c2 = 2;
                                break;
                            }
                            break;
                        case -1074341483:
                            if (strGroup2.equals("middle")) {
                                c2 = 3;
                                break;
                            }
                            break;
                        case 100571:
                            if (strGroup2.equals("end")) {
                                c2 = 4;
                                break;
                            }
                            break;
                        case 3317767:
                            if (strGroup2.equals("left")) {
                                c2 = 1;
                                break;
                            }
                            break;
                        case 108511772:
                            if (strGroup2.equals("right")) {
                                c2 = 5;
                                break;
                            }
                            break;
                        case 109757538:
                            if (strGroup2.equals("start")) {
                                c2 = 0;
                                break;
                            }
                            break;
                    }
                    if (c2 != 0) {
                        if (c2 == 1) {
                            i = 4;
                        } else if (c2 == 2 || c2 == 3) {
                            i = 2;
                        } else if (c2 == 4) {
                            i = 3;
                        } else if (c2 != 5) {
                            AbstractC2096gb.J("WebvttCueParser", "Invalid alignment value: ".concat(strGroup2));
                            i = 2;
                        } else {
                            i = 5;
                        }
                    }
                    g2.d = i;
                } else if ("position".equals(strGroup)) {
                    int iIndexOf2 = strGroup2.indexOf(44);
                    if (iIndexOf2 != -1) {
                        String strSubstring2 = strGroup2.substring(iIndexOf2 + 1);
                        switch (strSubstring2.hashCode()) {
                            case -1842484672:
                                if (strSubstring2.equals("line-left")) {
                                    c2 = 0;
                                    break;
                                }
                                break;
                            case -1364013995:
                                if (strSubstring2.equals("center")) {
                                    c2 = 2;
                                    break;
                                }
                                break;
                            case -1276788989:
                                if (strSubstring2.equals("line-right")) {
                                    c2 = 4;
                                    break;
                                }
                                break;
                            case -1074341483:
                                if (strSubstring2.equals("middle")) {
                                    c2 = 3;
                                    break;
                                }
                                break;
                            case 100571:
                                if (strSubstring2.equals("end")) {
                                    c2 = 5;
                                    break;
                                }
                                break;
                            case 109757538:
                                if (strSubstring2.equals("start")) {
                                    c2 = 1;
                                    break;
                                }
                                break;
                        }
                        if (c2 == 0 || c2 == 1) {
                            i = 0;
                        } else if (c2 != 2 && c2 != 3) {
                            if (c2 == 4 || c2 == 5) {
                                i = 2;
                            } else {
                                AbstractC2096gb.J("WebvttCueParser", "Invalid anchor value: ".concat(strSubstring2));
                                i = Integer.MIN_VALUE;
                            }
                        }
                        g2.i = i;
                        strGroup2 = strGroup2.substring(0, iIndexOf2);
                    }
                    g2.h = AbstractC1795We.a(strGroup2);
                } else if ("size".equals(strGroup)) {
                    g2.j = AbstractC1795We.a(strGroup2);
                } else if ("vertical".equals(strGroup)) {
                    int iHashCode = strGroup2.hashCode();
                    if (iHashCode != 3462) {
                        if (iHashCode == 3642 && strGroup2.equals("rl")) {
                            c2 = 0;
                        }
                    } else if (strGroup2.equals("lr")) {
                        c2 = 1;
                    }
                    if (c2 != 0) {
                        if (c2 != 1) {
                            AbstractC2096gb.J("WebvttCueParser", "Invalid 'vertical' value: ".concat(strGroup2));
                            i = Integer.MIN_VALUE;
                        } else {
                            i = 2;
                        }
                    }
                    g2.k = i;
                } else {
                    AbstractC2096gb.J("WebvttCueParser", "Unknown cue setting " + strGroup + ":" + strGroup2);
                }
            } catch (NumberFormatException unused) {
                AbstractC2096gb.J("WebvttCueParser", "Skipping bad cue setting: ".concat(String.valueOf(matcher.group())));
            }
        }
    }
}
