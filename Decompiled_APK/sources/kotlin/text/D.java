package kotlin.text;

import androidx.compose.animation.d0;
import kotlin.collections.AbstractC4916g;
import kotlin.collections.C4913d;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public class D extends StringsKt__StringNumberConversionsKt {
    public static String h(char[] cArr, int i, int i2) {
        Intrinsics.checkNotNullParameter(cArr, "<this>");
        C4913d c4913d = AbstractC4916g.a;
        int length = cArr.length;
        c4913d.getClass();
        C4913d.a(i, i2, length);
        return new String(cArr, i, i2 - i);
    }

    public static String i(byte[] bArr) {
        Intrinsics.checkNotNullParameter(bArr, "<this>");
        return new String(bArr, Charsets.UTF_8);
    }

    public static String j(int i, byte[] bArr, int i2) {
        Intrinsics.checkNotNullParameter(bArr, "<this>");
        C4913d c4913d = AbstractC4916g.a;
        int length = bArr.length;
        c4913d.getClass();
        C4913d.a(0, i, length);
        return new String(bArr, 0, i, Charsets.UTF_8);
    }

    public static boolean k(String str, String suffix, boolean z) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter(suffix, "suffix");
        return !z ? str.endsWith(suffix) : m(str.length() - suffix.length(), 0, suffix.length(), str, suffix, true);
    }

    public static boolean l(String str, String str2, boolean z) {
        return str == null ? str2 == null : !z ? str.equals(str2) : str.equalsIgnoreCase(str2);
    }

    public static boolean m(int i, int i2, int i3, String str, String other, boolean z) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter(other, "other");
        return !z ? str.regionMatches(i, other, i2, i3) : str.regionMatches(z, i, other, i2, i3);
    }

    public static String n(int i, String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        if (i < 0) {
            throw new IllegalArgumentException(d0.m('.', i, "Count 'n' must be non-negative, but was ").toString());
        }
        if (i == 0) {
            return "";
        }
        int i2 = 1;
        if (i == 1) {
            return str.toString();
        }
        int length = str.length();
        if (length == 0) {
            return "";
        }
        if (length == 1) {
            char cCharAt = str.charAt(0);
            char[] cArr = new char[i];
            for (int i3 = 0; i3 < i; i3++) {
                cArr[i3] = cCharAt;
            }
            return new String(cArr);
        }
        StringBuilder sb = new StringBuilder(str.length() * i);
        if (1 <= i) {
            while (true) {
                sb.append((CharSequence) str);
                if (i2 == i) {
                    break;
                }
                i2++;
            }
        }
        String string = sb.toString();
        Intrinsics.d(string);
        return string;
    }

    public static String o(String str, String oldValue, String newValue, boolean z) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter(oldValue, "oldValue");
        Intrinsics.checkNotNullParameter(newValue, "newValue");
        int i = 0;
        int iK = StringsKt.K(0, str, oldValue, z);
        if (iK < 0) {
            return str;
        }
        int length = oldValue.length();
        int i2 = length >= 1 ? length : 1;
        int length2 = newValue.length() + (str.length() - length);
        if (length2 < 0) {
            throw new OutOfMemoryError();
        }
        StringBuilder sb = new StringBuilder(length2);
        do {
            sb.append((CharSequence) str, i, iK);
            sb.append(newValue);
            i = iK + length;
            if (iK >= str.length()) {
                break;
            }
            iK = StringsKt.K(iK + i2, str, oldValue, z);
        } while (iK > 0);
        sb.append((CharSequence) str, i, str.length());
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }

    public static String p(String str, char c, char c2) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        String strReplace = str.replace(c, c2);
        Intrinsics.checkNotNullExpressionValue(strReplace, "replace(...)");
        return strReplace;
    }

    public static boolean q(String str, int i, String prefix, boolean z) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter(prefix, "prefix");
        return !z ? str.startsWith(prefix, i) : m(i, 0, prefix.length(), str, prefix, z);
    }

    public static boolean r(String str, String prefix, boolean z) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter(prefix, "prefix");
        return !z ? str.startsWith(prefix) : m(0, 0, prefix.length(), str, prefix, z);
    }
}
