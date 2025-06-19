package kotlin.text;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.C4930v;
import kotlin.collections.C4933y;
import kotlin.collections.N;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;

/* JADX INFO: Access modifiers changed from: package-private */
@Metadata
/* loaded from: classes3.dex */
public class StringsKt__StringsKt extends D {
    public static final boolean s(int i, String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        return i >= 0 && i <= str.length() + (-2) && Character.isHighSurrogate(str.charAt(i)) && Character.isLowSurrogate(str.charAt(i + 1));
    }

    public static List split$default(CharSequence charSequence, String[] delimiters, boolean z, int i, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = false;
        }
        if ((i2 & 4) != 0) {
            i = 0;
        }
        Intrinsics.checkNotNullParameter(charSequence, "<this>");
        Intrinsics.checkNotNullParameter(delimiters, "delimiters");
        if (delimiters.length == 1) {
            String str = delimiters[0];
            if (str.length() != 0) {
                return z(i, charSequence, str, z);
            }
        }
        C4964c c4964cW = w(charSequence, delimiters, z, i);
        Intrinsics.checkNotNullParameter(c4964cW, "<this>");
        N n = new N(c4964cW, 1);
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(n, 10));
        Iterator it2 = n.iterator();
        while (true) {
            C4963b c4963b = (C4963b) it2;
            if (!c4963b.hasNext()) {
                return arrayList;
            }
            arrayList.add(StringsKt.Y(charSequence, (IntRange) c4963b.next()));
        }
    }

    public static final int t(CharSequence charSequence, CharSequence charSequence2, int i, int i2, boolean z, boolean z2) {
        kotlin.ranges.h hVar;
        if (z2) {
            int iJ = StringsKt.J(charSequence);
            if (i > iJ) {
                i = iJ;
            }
            if (i2 < 0) {
                i2 = 0;
            }
            kotlin.ranges.h.d.getClass();
            hVar = new kotlin.ranges.h(i, i2, -1);
        } else {
            if (i < 0) {
                i = 0;
            }
            int length = charSequence.length();
            if (i2 > length) {
                i2 = length;
            }
            hVar = new IntRange(i, i2, 1);
        }
        boolean z3 = charSequence instanceof String;
        int i3 = hVar.c;
        int i4 = hVar.b;
        int i5 = hVar.a;
        if (!z3 || !(charSequence2 instanceof String)) {
            boolean z4 = z;
            if ((i3 > 0 && i5 <= i4) || (i3 < 0 && i4 <= i5)) {
                while (true) {
                    CharSequence charSequence3 = charSequence;
                    CharSequence charSequence4 = charSequence2;
                    boolean z5 = z4;
                    z4 = z5;
                    if (!x(charSequence4, 0, charSequence3, i5, charSequence2.length(), z5)) {
                        if (i5 == i4) {
                            break;
                        }
                        i5 += i3;
                        charSequence2 = charSequence4;
                        charSequence = charSequence3;
                    } else {
                        return i5;
                    }
                }
            }
        } else if ((i3 > 0 && i5 <= i4) || (i3 < 0 && i4 <= i5)) {
            int i6 = i5;
            while (true) {
                boolean z6 = z;
                if (!D.m(0, i6, ((String) charSequence2).length(), (String) charSequence2, (String) charSequence, z6)) {
                    if (i6 == i4) {
                        break;
                    }
                    i6 += i3;
                    z = z6;
                } else {
                    return i6;
                }
            }
        }
        return -1;
    }

    public static final int u(CharSequence charSequence, char[] chars, int i, boolean z) {
        Intrinsics.checkNotNullParameter(charSequence, "<this>");
        Intrinsics.checkNotNullParameter(chars, "chars");
        if (!z && chars.length == 1 && (charSequence instanceof String)) {
            return ((String) charSequence).indexOf(C4933y.J(chars), i);
        }
        if (i < 0) {
            i = 0;
        }
        int iJ = StringsKt.J(charSequence);
        if (i > iJ) {
            return -1;
        }
        while (true) {
            char cCharAt = charSequence.charAt(i);
            for (char c : chars) {
                if (C4962a.a(c, cCharAt, z)) {
                    return i;
                }
            }
            if (i == iJ) {
                return -1;
            }
            i++;
        }
    }

    public static final kotlin.sequences.t v(CharSequence charSequence) {
        Intrinsics.checkNotNullParameter(charSequence, "<this>");
        String[] delimiters = {"\r\n", "\n", "\r"};
        Intrinsics.checkNotNullParameter(charSequence, "<this>");
        Intrinsics.checkNotNullParameter(delimiters, "delimiters");
        return kotlin.sequences.q.h(w(charSequence, delimiters, false, 0), new G(charSequence));
    }

    public static C4964c w(CharSequence charSequence, String[] strArr, boolean z, int i) {
        y(i);
        return new C4964c(charSequence, i, new F(C4930v.c(strArr), z));
    }

    public static final boolean x(CharSequence charSequence, int i, CharSequence other, int i2, int i3, boolean z) {
        Intrinsics.checkNotNullParameter(charSequence, "<this>");
        Intrinsics.checkNotNullParameter(other, "other");
        if (i2 < 0 || i < 0 || i > charSequence.length() - i3 || i2 > other.length() - i3) {
            return false;
        }
        for (int i4 = 0; i4 < i3; i4++) {
            if (!C4962a.a(charSequence.charAt(i + i4), other.charAt(i2 + i4), z)) {
                return false;
            }
        }
        return true;
    }

    public static final void y(int i) {
        if (i < 0) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "Limit must be non-negative, but was ").toString());
        }
    }

    public static final List z(int i, CharSequence charSequence, String str, boolean z) {
        y(i);
        int length = 0;
        int iK = StringsKt.K(0, charSequence, str, z);
        if (iK == -1 || i == 1) {
            return kotlin.collections.A.b(charSequence.toString());
        }
        boolean z2 = i > 0;
        int i2 = 10;
        if (z2 && i <= 10) {
            i2 = i;
        }
        ArrayList arrayList = new ArrayList(i2);
        do {
            arrayList.add(charSequence.subSequence(length, iK).toString());
            length = str.length() + iK;
            if (z2 && arrayList.size() == i - 1) {
                break;
            }
            iK = StringsKt.K(length, charSequence, str, z);
        } while (iK != -1);
        arrayList.add(charSequence.subSequence(length, charSequence.length()).toString());
        return arrayList;
    }
}
