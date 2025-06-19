package kotlin.text;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.C4933y;
import kotlin.collections.N;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;

@Metadata
/* loaded from: classes3.dex */
public final class StringsKt extends I {
    private StringsKt() {
    }

    public static String E(String str, String other) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter(other, "other");
        int length = str.length();
        int iMin = Math.min(length, other.length());
        int i = 0;
        while (i < iMin && C4962a.a(str.charAt((length - i) - 1), other.charAt((r1 - i) - 1), false)) {
            i++;
        }
        if (StringsKt__StringsKt.s((length - i) - 1, str) || StringsKt__StringsKt.s((r1 - i) - 1, other)) {
            i--;
        }
        return str.subSequence(length - i, length).toString();
    }

    public static boolean F(CharSequence charSequence, char c, boolean z) {
        Intrinsics.checkNotNullParameter(charSequence, "<this>");
        return L(charSequence, c, 0, z, 2) >= 0;
    }

    public static boolean G(CharSequence charSequence, CharSequence other, boolean z) {
        Intrinsics.checkNotNullParameter(charSequence, "<this>");
        Intrinsics.checkNotNullParameter(other, "other");
        if (other instanceof String) {
            if (M(charSequence, (String) other, 0, z, 2) >= 0) {
                return true;
            }
        } else if (StringsKt__StringsKt.t(charSequence, other, 0, charSequence.length(), z, false) >= 0) {
            return true;
        }
        return false;
    }

    public static boolean H(CharSequence charSequence, String suffix) {
        Intrinsics.checkNotNullParameter(charSequence, "<this>");
        Intrinsics.checkNotNullParameter(suffix, "suffix");
        return (!(charSequence instanceof String) || suffix == null) ? StringsKt__StringsKt.x(charSequence, charSequence.length() - suffix.length(), suffix, 0, suffix.length(), false) : D.k((String) charSequence, suffix, false);
    }

    public static boolean I(String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        return str.length() > 0 && C4962a.a(str.charAt(J(str)), '/', false);
    }

    public static int J(CharSequence charSequence) {
        Intrinsics.checkNotNullParameter(charSequence, "<this>");
        return charSequence.length() - 1;
    }

    public static int K(int i, CharSequence charSequence, String string, boolean z) {
        Intrinsics.checkNotNullParameter(charSequence, "<this>");
        Intrinsics.checkNotNullParameter(string, "string");
        return (z || !(charSequence instanceof String)) ? StringsKt__StringsKt.t(charSequence, string, i, charSequence.length(), z, false) : ((String) charSequence).indexOf(string, i);
    }

    public static int L(CharSequence charSequence, char c, int i, boolean z, int i2) {
        if ((i2 & 2) != 0) {
            i = 0;
        }
        if ((i2 & 4) != 0) {
            z = false;
        }
        Intrinsics.checkNotNullParameter(charSequence, "<this>");
        return (z || !(charSequence instanceof String)) ? StringsKt__StringsKt.u(charSequence, new char[]{c}, i, z) : ((String) charSequence).indexOf(c, i);
    }

    public static /* synthetic */ int M(CharSequence charSequence, String str, int i, boolean z, int i2) {
        if ((i2 & 2) != 0) {
            i = 0;
        }
        if ((i2 & 4) != 0) {
            z = false;
        }
        return K(i, charSequence, str, z);
    }

    public static boolean O(CharSequence charSequence) {
        Intrinsics.checkNotNullParameter(charSequence, "<this>");
        for (int i = 0; i < charSequence.length(); i++) {
            if (!CharsKt.b(charSequence.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    public static int P(CharSequence charSequence, char c, int i, int i2) {
        if ((i2 & 2) != 0) {
            i = J(charSequence);
        }
        Intrinsics.checkNotNullParameter(charSequence, "<this>");
        if (charSequence instanceof String) {
            return ((String) charSequence).lastIndexOf(c, i);
        }
        char[] chars = {c};
        Intrinsics.checkNotNullParameter(charSequence, "<this>");
        Intrinsics.checkNotNullParameter(chars, "chars");
        if (charSequence instanceof String) {
            return ((String) charSequence).lastIndexOf(C4933y.J(chars), i);
        }
        int iJ = J(charSequence);
        if (i > iJ) {
            i = iJ;
        }
        while (-1 < i) {
            if (C4962a.a(chars[0], charSequence.charAt(i), false)) {
                return i;
            }
            i--;
        }
        return -1;
    }

    public static int Q(CharSequence charSequence, String string, int i, int i2) {
        if ((i2 & 2) != 0) {
            i = J(charSequence);
        }
        int i3 = i;
        Intrinsics.checkNotNullParameter(charSequence, "<this>");
        Intrinsics.checkNotNullParameter(string, "string");
        return !(charSequence instanceof String) ? StringsKt__StringsKt.t(charSequence, string, i3, 0, false, true) : ((String) charSequence).lastIndexOf(string, i3);
    }

    public static List R(CharSequence charSequence) {
        Intrinsics.checkNotNullParameter(charSequence, "<this>");
        return kotlin.sequences.q.j(StringsKt__StringsKt.v(charSequence));
    }

    public static String S(char c, int i, String str) {
        CharSequence charSequenceSubSequence;
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter(str, "<this>");
        if (i < 0) {
            throw new IllegalArgumentException(AbstractC0147y.c(i, "Desired length ", " is less than zero."));
        }
        if (i <= str.length()) {
            charSequenceSubSequence = str.subSequence(0, str.length());
        } else {
            StringBuilder sb = new StringBuilder(i);
            int length = i - str.length();
            int i2 = 1;
            if (1 <= length) {
                while (true) {
                    sb.append(c);
                    if (i2 == length) {
                        break;
                    }
                    i2++;
                }
            }
            sb.append((CharSequence) str);
            charSequenceSubSequence = sb;
        }
        return charSequenceSubSequence.toString();
    }

    public static String T(String str, String prefix) {
        String str2;
        String str3;
        boolean zX;
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter(prefix, "prefix");
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter(prefix, "prefix");
        if (str != null) {
            zX = D.r(str, prefix, false);
            str2 = str;
            str3 = prefix;
        } else {
            str2 = str;
            str3 = prefix;
            zX = StringsKt__StringsKt.x(str2, 0, str3, 0, prefix.length(), false);
        }
        if (!zX) {
            return str2;
        }
        String strSubstring = str2.substring(str3.length());
        Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
        return strSubstring;
    }

    public static String U(String str, String suffix) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter(suffix, "suffix");
        if (!H(str, suffix)) {
            return str;
        }
        String strSubstring = str.substring(0, str.length() - suffix.length());
        Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
        return strSubstring;
    }

    public static List V(CharSequence charSequence, char[] delimiters) {
        Intrinsics.checkNotNullParameter(charSequence, "<this>");
        Intrinsics.checkNotNullParameter(delimiters, "delimiters");
        if (delimiters.length == 1) {
            return StringsKt__StringsKt.z(0, charSequence, String.valueOf(delimiters[0]), false);
        }
        StringsKt__StringsKt.y(0);
        C4964c c4964c = new C4964c(charSequence, 0, new E(delimiters));
        Intrinsics.checkNotNullParameter(c4964c, "<this>");
        N n = new N(c4964c, 1);
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(n, 10));
        Iterator it2 = n.iterator();
        while (true) {
            C4963b c4963b = (C4963b) it2;
            if (!c4963b.hasNext()) {
                return arrayList;
            }
            arrayList.add(Y(charSequence, (IntRange) c4963b.next()));
        }
    }

    public static boolean X(String str, char c) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        return str.length() > 0 && C4962a.a(str.charAt(0), c, false);
    }

    public static String Y(CharSequence charSequence, IntRange range) {
        Intrinsics.checkNotNullParameter(charSequence, "<this>");
        Intrinsics.checkNotNullParameter(range, "range");
        return charSequence.subSequence(range.a, range.b + 1).toString();
    }

    public static String Z(String str, IntRange range) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter(range, "range");
        String strSubstring = str.substring(range.a, range.b + 1);
        Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
        return strSubstring;
    }

    public static String a0(String str, String missingDelimiterValue, char c) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter(missingDelimiterValue, "missingDelimiterValue");
        int iL = L(str, c, 0, false, 6);
        if (iL == -1) {
            return missingDelimiterValue;
        }
        String strSubstring = str.substring(iL + 1, str.length());
        Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
        return strSubstring;
    }

    public static String b0(String missingDelimiterValue, String delimiter) {
        Intrinsics.checkNotNullParameter(missingDelimiterValue, "<this>");
        Intrinsics.checkNotNullParameter(delimiter, "delimiter");
        Intrinsics.checkNotNullParameter(missingDelimiterValue, "missingDelimiterValue");
        int iM = M(missingDelimiterValue, delimiter, 0, false, 6);
        if (iM == -1) {
            return missingDelimiterValue;
        }
        String strSubstring = missingDelimiterValue.substring(delimiter.length() + iM, missingDelimiterValue.length());
        Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
        return strSubstring;
    }

    public static String c0(String str, String missingDelimiterValue, char c) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter(missingDelimiterValue, "missingDelimiterValue");
        int iP = P(str, c, 0, 6);
        if (iP == -1) {
            return missingDelimiterValue;
        }
        String strSubstring = str.substring(iP + 1, str.length());
        Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
        return strSubstring;
    }

    public static String d0(String missingDelimiterValue, char c) {
        Intrinsics.checkNotNullParameter(missingDelimiterValue, "<this>");
        Intrinsics.checkNotNullParameter(missingDelimiterValue, "missingDelimiterValue");
        int iL = L(missingDelimiterValue, c, 0, false, 6);
        if (iL == -1) {
            return missingDelimiterValue;
        }
        String strSubstring = missingDelimiterValue.substring(0, iL);
        Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
        return strSubstring;
    }

    public static String e0(String missingDelimiterValue, char c) {
        Intrinsics.checkNotNullParameter(missingDelimiterValue, "<this>");
        Intrinsics.checkNotNullParameter(missingDelimiterValue, "missingDelimiterValue");
        int iP = P(missingDelimiterValue, c, 0, 6);
        if (iP == -1) {
            return missingDelimiterValue;
        }
        String strSubstring = missingDelimiterValue.substring(0, iP);
        Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
        return strSubstring;
    }

    public static Long f0(String str) {
        boolean z;
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter(str, "<this>");
        CharsKt__CharJVMKt.checkRadix(10);
        int length = str.length();
        if (length == 0) {
            return null;
        }
        int i = 0;
        char cCharAt = str.charAt(0);
        long j = -9223372036854775807L;
        if (Intrinsics.g(cCharAt, 48) < 0) {
            z = true;
            if (length == 1) {
                return null;
            }
            if (cCharAt == '+') {
                z = false;
                i = 1;
            } else {
                if (cCharAt != '-') {
                    return null;
                }
                j = Long.MIN_VALUE;
                i = 1;
            }
        } else {
            z = false;
        }
        long j2 = 0;
        long j3 = -256204778801521550L;
        while (i < length) {
            int iDigit = Character.digit((int) str.charAt(i), 10);
            if (iDigit < 0) {
                return null;
            }
            if (j2 < j3) {
                if (j3 != -256204778801521550L) {
                    return null;
                }
                j3 = j / 10;
                if (j2 < j3) {
                    return null;
                }
            }
            long j4 = j2 * 10;
            long j5 = iDigit;
            if (j4 < j + j5) {
                return null;
            }
            j2 = j4 - j5;
            i++;
        }
        return z ? Long.valueOf(j2) : Long.valueOf(-j2);
    }

    public static CharSequence g0(CharSequence charSequence) {
        Intrinsics.checkNotNullParameter(charSequence, "<this>");
        int length = charSequence.length() - 1;
        int i = 0;
        boolean z = false;
        while (i <= length) {
            boolean zB = CharsKt.b(charSequence.charAt(!z ? i : length));
            if (z) {
                if (!zB) {
                    break;
                }
                length--;
            } else if (zB) {
                i++;
            } else {
                z = true;
            }
        }
        return charSequence.subSequence(i, length + 1);
    }

    public static CharSequence h0(StringBuilder sb) {
        Intrinsics.checkNotNullParameter(sb, "<this>");
        int length = sb.length() - 1;
        if (length < 0) {
            return "";
        }
        while (true) {
            int i = length - 1;
            if (!CharsKt.b(sb.charAt(length))) {
                return sb.subSequence(0, length + 1);
            }
            if (i < 0) {
                return "";
            }
            length = i;
        }
    }
}
