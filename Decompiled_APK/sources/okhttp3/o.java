package okhttp3;

import androidx.compose.animation.d0;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import kotlin.text.StringsKt;
import okio.C5091h;

/* loaded from: classes3.dex */
public final class o implements InterfaceC5073b {
    public static final o b = new o();
    public static final o c = new o();

    public static final C5081j a(o oVar, String str) {
        C5081j c5081j = new C5081j(str);
        C5081j.d.put(str, c5081j);
        return c5081j;
    }

    public static String b(int i, int i2, int i3, String str, String encodeSet, boolean z) {
        boolean z2 = false;
        int i4 = (i3 & 1) != 0 ? 0 : i;
        int length = (i3 & 2) != 0 ? str.length() : i2;
        boolean z3 = (i3 & 8) != 0 ? false : z;
        boolean z4 = (i3 & 16) == 0;
        boolean z5 = (i3 & 32) == 0;
        boolean z6 = (i3 & 64) == 0;
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter(encodeSet, "encodeSet");
        int iCharCount = i4;
        while (iCharCount < length) {
            int iCodePointAt = str.codePointAt(iCharCount);
            int i5 = 32;
            int i6 = 43;
            if (iCodePointAt < 32 || iCodePointAt == 127 || ((iCodePointAt >= 128 && !z6) || StringsKt.F(encodeSet, (char) iCodePointAt, false) || ((iCodePointAt == 37 && (!z3 || (z4 && !e(iCharCount, length, str)))) || (iCodePointAt == 43 && z5)))) {
                C5091h c5091h = new C5091h();
                c5091h.t0(i4, iCharCount, str);
                C5091h c5091h2 = null;
                while (iCharCount < length) {
                    int iCodePointAt2 = str.codePointAt(iCharCount);
                    if (!z3 || (iCodePointAt2 != 9 && iCodePointAt2 != 10 && iCodePointAt2 != 12 && iCodePointAt2 != 13)) {
                        if (iCodePointAt2 == i6 && z5) {
                            c5091h.u0(z3 ? "+" : "%2B");
                        } else {
                            if (iCodePointAt2 >= i5 && iCodePointAt2 != 127) {
                                if ((iCodePointAt2 < 128 || z6) && !StringsKt.F(encodeSet, (char) iCodePointAt2, z2) && (iCodePointAt2 != 37 || (z3 && (!z4 || e(iCharCount, length, str))))) {
                                    c5091h.v0(iCodePointAt2);
                                }
                            }
                            if (c5091h2 == null) {
                                c5091h2 = new C5091h();
                            }
                            c5091h2.v0(iCodePointAt2);
                            while (!c5091h2.u()) {
                                byte b2 = c5091h2.readByte();
                                c5091h.p0(37);
                                char[] cArr = s.k;
                                c5091h.p0(cArr[((b2 & 255) >> 4) & 15]);
                                c5091h.p0(cArr[b2 & 15]);
                            }
                        }
                    }
                    iCharCount += Character.charCount(iCodePointAt2);
                    z2 = false;
                    i5 = 32;
                    i6 = 43;
                }
                return c5091h.U();
            }
            iCharCount += Character.charCount(iCodePointAt);
        }
        String strSubstring = str.substring(i4, length);
        Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String…ing(startIndex, endIndex)");
        return strSubstring;
    }

    public static I c(String string) {
        Intrinsics.checkNotNullParameter(string, "<this>");
        Charset charset = Charsets.UTF_8;
        C5091h c5091h = new C5091h();
        Intrinsics.checkNotNullParameter(string, "string");
        Intrinsics.checkNotNullParameter(charset, "charset");
        int length = string.length();
        Intrinsics.checkNotNullParameter(string, "string");
        Intrinsics.checkNotNullParameter(charset, "charset");
        if (length < 0) {
            throw new IllegalArgumentException(d0.p("endIndex < beginIndex: ", length, " < ", 0).toString());
        }
        if (length > string.length()) {
            StringBuilder sbV = android.support.v4.media.session.a.v(length, "endIndex > string.length: ", " > ");
            sbV.append(string.length());
            throw new IllegalArgumentException(sbV.toString().toString());
        }
        if (Intrinsics.b(charset, Charsets.UTF_8)) {
            c5091h.t0(0, length, string);
        } else {
            String strSubstring = string.substring(0, length);
            Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
            byte[] bytes = strSubstring.getBytes(charset);
            Intrinsics.checkNotNullExpressionValue(bytes, "getBytes(...)");
            c5091h.o0(bytes, 0, bytes.length);
        }
        long j = c5091h.b;
        Intrinsics.checkNotNullParameter(c5091h, "<this>");
        return new I((w) null, j, c5091h);
    }

    public static boolean e(int i, int i2, String str) {
        int i3 = i + 2;
        return i3 < i2 && str.charAt(i) == '%' && okhttp3.internal.b.s(str.charAt(i + 1)) != -1 && okhttp3.internal.b.s(str.charAt(i3)) != -1;
    }

    public static String f(int i, int i2, String str, int i3) {
        int i4;
        if ((i3 & 1) != 0) {
            i = 0;
        }
        if ((i3 & 2) != 0) {
            i2 = str.length();
        }
        boolean z = (i3 & 4) == 0;
        Intrinsics.checkNotNullParameter(str, "<this>");
        int iCharCount = i;
        while (iCharCount < i2) {
            char cCharAt = str.charAt(iCharCount);
            if (cCharAt == '%' || (cCharAt == '+' && z)) {
                C5091h c5091h = new C5091h();
                c5091h.t0(i, iCharCount, str);
                while (iCharCount < i2) {
                    int iCodePointAt = str.codePointAt(iCharCount);
                    if (iCodePointAt == 37 && (i4 = iCharCount + 2) < i2) {
                        int iS = okhttp3.internal.b.s(str.charAt(iCharCount + 1));
                        int iS2 = okhttp3.internal.b.s(str.charAt(i4));
                        if (iS == -1 || iS2 == -1) {
                            c5091h.v0(iCodePointAt);
                            iCharCount += Character.charCount(iCodePointAt);
                        } else {
                            c5091h.p0((iS << 4) + iS2);
                            iCharCount = Character.charCount(iCodePointAt) + i4;
                        }
                    } else if (iCodePointAt == 43 && z) {
                        c5091h.p0(32);
                        iCharCount++;
                    } else {
                        c5091h.v0(iCodePointAt);
                        iCharCount += Character.charCount(iCodePointAt);
                    }
                }
                return c5091h.U();
            }
            iCharCount++;
        }
        String strSubstring = str.substring(i, i2);
        Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String…ing(startIndex, endIndex)");
        return strSubstring;
    }

    public static String g(String str) {
        if (kotlin.text.D.r(str, "TLS_", false)) {
            StringBuilder sb = new StringBuilder("SSL_");
            String strSubstring = str.substring(4);
            Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String).substring(startIndex)");
            sb.append(strSubstring);
            return sb.toString();
        }
        if (!kotlin.text.D.r(str, "SSL_", false)) {
            return str;
        }
        StringBuilder sb2 = new StringBuilder("TLS_");
        String strSubstring2 = str.substring(4);
        Intrinsics.checkNotNullExpressionValue(strSubstring2, "this as java.lang.String).substring(startIndex)");
        sb2.append(strSubstring2);
        return sb2.toString();
    }

    public static ArrayList h(String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        ArrayList arrayList = new ArrayList();
        int i = 0;
        while (i <= str.length()) {
            int iL = StringsKt.L(str, '&', i, false, 4);
            if (iL == -1) {
                iL = str.length();
            }
            int iL2 = StringsKt.L(str, '=', i, false, 4);
            if (iL2 == -1 || iL2 > iL) {
                String strSubstring = str.substring(i, iL);
                Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String…ing(startIndex, endIndex)");
                arrayList.add(strSubstring);
                arrayList.add(null);
            } else {
                String strSubstring2 = str.substring(i, iL2);
                Intrinsics.checkNotNullExpressionValue(strSubstring2, "this as java.lang.String…ing(startIndex, endIndex)");
                arrayList.add(strSubstring2);
                String strSubstring3 = str.substring(iL2 + 1, iL);
                Intrinsics.checkNotNullExpressionValue(strSubstring3, "this as java.lang.String…ing(startIndex, endIndex)");
                arrayList.add(strSubstring3);
            }
            i = iL + 1;
        }
        return arrayList;
    }

    public static void i(ArrayList arrayList, StringBuilder out) {
        Intrinsics.checkNotNullParameter(arrayList, "<this>");
        Intrinsics.checkNotNullParameter(out, "out");
        kotlin.ranges.h hVarG = kotlin.ranges.l.g(2, kotlin.ranges.l.h(0, arrayList.size()));
        int i = hVarG.a;
        int i2 = hVarG.b;
        int i3 = hVarG.c;
        if ((i3 <= 0 || i > i2) && (i3 >= 0 || i2 > i)) {
            return;
        }
        while (true) {
            String str = (String) arrayList.get(i);
            String str2 = (String) arrayList.get(i + 1);
            if (i > 0) {
                out.append('&');
            }
            out.append(str);
            if (str2 != null) {
                out.append('=');
                out.append(str2);
            }
            if (i == i2) {
                return;
            } else {
                i += i3;
            }
        }
    }

    public synchronized C5081j d(String javaName) {
        C5081j c5081j;
        try {
            Intrinsics.checkNotNullParameter(javaName, "javaName");
            LinkedHashMap linkedHashMap = C5081j.d;
            c5081j = (C5081j) linkedHashMap.get(javaName);
            if (c5081j == null) {
                c5081j = (C5081j) linkedHashMap.get(g(javaName));
                if (c5081j == null) {
                    c5081j = new C5081j(javaName);
                }
                linkedHashMap.put(javaName, c5081j);
            }
        } catch (Throwable th) {
            throw th;
        }
        return c5081j;
    }
}
