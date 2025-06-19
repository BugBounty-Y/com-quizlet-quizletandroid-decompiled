package io.ktor.http;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3099a7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3108b7;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.CharsKt;
import kotlin.text.StringsKt;
import kotlin.text.StringsKt__StringsKt;

/* loaded from: classes3.dex */
public abstract class x {
    public static final List a = kotlin.collections.A.b("");

    public static final int a(int i, int i2, String str) {
        boolean z = false;
        while (i < i2) {
            char cCharAt = str.charAt(i);
            if (cCharAt != ':') {
                if (cCharAt == '[') {
                    z = true;
                } else if (cCharAt == ']') {
                    z = false;
                }
            } else if (!z) {
                return i;
            }
            i++;
        }
        return -1;
    }

    public static final w b(w wVar, String urlString) {
        Intrinsics.checkNotNullParameter(wVar, "<this>");
        Intrinsics.checkNotNullParameter(urlString, "urlString");
        if (StringsKt.O(urlString)) {
            return wVar;
        }
        try {
            c(wVar, urlString);
            return wVar;
        } catch (Throwable cause) {
            Intrinsics.checkNotNullParameter(urlString, "urlString");
            Intrinsics.checkNotNullParameter(cause, "cause");
            throw new URLParserException("Fail to parse url: ".concat(urlString), cause);
        }
    }

    public static final void c(w wVar, String urlString) throws NumberFormatException {
        int i;
        int i2;
        int i3;
        int i4;
        int i5;
        int i6;
        int i7;
        io.ktor.util.l vVar;
        int i8;
        List listV;
        int iIntValue;
        int i9;
        int i10 = 1;
        Intrinsics.checkNotNullParameter(wVar, "<this>");
        Intrinsics.checkNotNullParameter(urlString, "urlString");
        int length = urlString.length();
        int i11 = 0;
        while (true) {
            if (i11 >= length) {
                i11 = -1;
                break;
            } else if (!CharsKt.b(urlString.charAt(i11))) {
                break;
            } else {
                i11++;
            }
        }
        int length2 = urlString.length() - 1;
        if (length2 >= 0) {
            while (true) {
                int i12 = length2 - 1;
                if (!CharsKt.b(urlString.charAt(length2))) {
                    break;
                } else if (i12 < 0) {
                    break;
                } else {
                    length2 = i12;
                }
            }
            length2 = -1;
        } else {
            length2 = -1;
        }
        int i13 = length2 + 1;
        char cCharAt = urlString.charAt(i11);
        if (('a' > cCharAt || cCharAt >= '{') && ('A' > cCharAt || cCharAt >= '[')) {
            i = i11;
            i2 = i;
        } else {
            i2 = -1;
            i = i11;
        }
        while (true) {
            i3 = i10;
            if (i >= i13) {
                break;
            }
            char cCharAt2 = urlString.charAt(i);
            if (cCharAt2 == ':') {
                if (i2 != -1) {
                    throw new IllegalArgumentException(android.support.v4.media.session.a.f(i2, "Illegal character in scheme at position "));
                }
                i4 = i - i11;
            } else {
                if (cCharAt2 == '#' || cCharAt2 == '/' || cCharAt2 == '?') {
                    break;
                }
                if (i2 == -1 && (('a' > cCharAt2 || cCharAt2 >= '{') && (('A' > cCharAt2 || cCharAt2 >= '[') && (('0' > cCharAt2 || cCharAt2 >= ':') && cCharAt2 != '.' && cCharAt2 != '+' && cCharAt2 != '-')))) {
                    i2 = i;
                }
                i++;
                i10 = i3;
            }
        }
        i4 = -1;
        if (i4 > 0) {
            String name = urlString.substring(i11, i11 + i4);
            Intrinsics.checkNotNullExpressionValue(name, "substring(...)");
            y yVar = y.c;
            Intrinsics.checkNotNullParameter(name, "name");
            Intrinsics.checkNotNullParameter(name, "<this>");
            int length3 = name.length();
            int i14 = 0;
            while (true) {
                if (i14 >= length3) {
                    i14 = -1;
                    break;
                }
                char cCharAt3 = name.charAt(i14);
                if ((('A' > cCharAt3 || cCharAt3 >= '[') ? (cCharAt3 < 0 || cCharAt3 >= 128) ? Character.toLowerCase(cCharAt3) : cCharAt3 : (char) (cCharAt3 + ' ')) != cCharAt3) {
                    break;
                } else {
                    i14++;
                }
            }
            if (i14 != -1) {
                StringBuilder sb = new StringBuilder(name.length());
                sb.append((CharSequence) name, 0, i14);
                int iJ = StringsKt.J(name);
                if (i14 <= iJ) {
                    while (true) {
                        char cCharAt4 = name.charAt(i14);
                        if ('A' <= cCharAt4 && cCharAt4 < '[') {
                            cCharAt4 = (char) (cCharAt4 + ' ');
                        } else if (cCharAt4 < 0 || cCharAt4 >= 128) {
                            cCharAt4 = Character.toLowerCase(cCharAt4);
                        }
                        sb.append(cCharAt4);
                        if (i14 == iJ) {
                            break;
                        } else {
                            i14++;
                        }
                    }
                }
                name = sb.toString();
                Intrinsics.checkNotNullExpressionValue(name, "toString(...)");
            }
            y value = (y) y.d.get(name);
            if (value == null) {
                value = new y(name, 0);
            }
            wVar.getClass();
            Intrinsics.checkNotNullParameter(value, "value");
            wVar.d = value;
            i11 += i4 + 1;
        }
        int i15 = 0;
        while (true) {
            i5 = i11 + i15;
            if (i5 >= i13 || urlString.charAt(i5) != '/') {
                break;
            } else {
                i15++;
            }
        }
        if (Intrinsics.b(wVar.c().a, "file")) {
            if (i15 != 2) {
                if (i15 != 3) {
                    throw new IllegalArgumentException("Invalid file url: ".concat(urlString));
                }
                Intrinsics.checkNotNullParameter("", "<set-?>");
                wVar.a = "";
                StringBuilder sb2 = new StringBuilder("/");
                String strSubstring = urlString.substring(i5, i13);
                Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                sb2.append(strSubstring);
                AbstractC3108b7.i(wVar, sb2.toString());
                return;
            }
            int iL = StringsKt.L(urlString, '/', i5, false, 4);
            if (iL == -1 || iL == i13) {
                String strSubstring2 = urlString.substring(i5, i13);
                Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
                wVar.d(strSubstring2);
                return;
            } else {
                String strSubstring3 = urlString.substring(i5, iL);
                Intrinsics.checkNotNullExpressionValue(strSubstring3, "substring(...)");
                wVar.d(strSubstring3);
                String strSubstring4 = urlString.substring(iL, i13);
                Intrinsics.checkNotNullExpressionValue(strSubstring4, "substring(...)");
                AbstractC3108b7.i(wVar, strSubstring4);
                return;
            }
        }
        if (Intrinsics.b(wVar.c().a, "mailto")) {
            if (i15 != 0) {
                throw new IllegalArgumentException("Failed requirement.");
            }
            int iM = StringsKt.M(urlString, "@", i5, false, 4);
            if (iM == -1) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.B("Invalid mailto url: ", urlString, ", it should contain '@'."));
            }
            String strSubstring5 = urlString.substring(i5, iM);
            Intrinsics.checkNotNullExpressionValue(strSubstring5, "substring(...)");
            String strC = AbstractC4879a.c(strSubstring5);
            wVar.e = strC != null ? AbstractC4879a.e(strC, false) : null;
            String strSubstring6 = urlString.substring(iM + 1, i13);
            Intrinsics.checkNotNullExpressionValue(strSubstring6, "substring(...)");
            wVar.d(strSubstring6);
            return;
        }
        if (Intrinsics.b(wVar.c().a, "about")) {
            if (i15 != 0) {
                throw new IllegalArgumentException("Failed requirement.");
            }
            String strSubstring7 = urlString.substring(i5, i13);
            Intrinsics.checkNotNullExpressionValue(strSubstring7, "substring(...)");
            wVar.d(strSubstring7);
            return;
        }
        if (i15 >= 2) {
            while (true) {
                Intrinsics.checkNotNullParameter("@/\\?#", "<this>");
                char[] cArr = new char[5];
                for (int i16 = 0; i16 < 5; i16++) {
                    cArr[i16] = "@/\\?#".charAt(i16);
                }
                int iU = StringsKt__StringsKt.u(urlString, cArr, i5, false);
                Integer numValueOf = Integer.valueOf(iU);
                if (iU <= 0) {
                    numValueOf = null;
                }
                iIntValue = numValueOf != null ? numValueOf.intValue() : i13;
                if (iIntValue >= i13 || urlString.charAt(iIntValue) != '@') {
                    break;
                }
                int iA = a(i5, iIntValue, urlString);
                if (iA != -1) {
                    String strSubstring8 = urlString.substring(i5, iA);
                    Intrinsics.checkNotNullExpressionValue(strSubstring8, "substring(...)");
                    wVar.e = strSubstring8;
                    String strSubstring9 = urlString.substring(iA + 1, iIntValue);
                    Intrinsics.checkNotNullExpressionValue(strSubstring9, "substring(...)");
                    wVar.f = strSubstring9;
                } else {
                    String strSubstring10 = urlString.substring(i5, iIntValue);
                    Intrinsics.checkNotNullExpressionValue(strSubstring10, "substring(...)");
                    wVar.e = strSubstring10;
                }
                i5 = iIntValue + 1;
            }
            int iA2 = a(i5, iIntValue, urlString);
            Integer numValueOf2 = Integer.valueOf(iA2);
            if (iA2 <= 0) {
                numValueOf2 = null;
            }
            int iIntValue2 = numValueOf2 != null ? numValueOf2.intValue() : iIntValue;
            String strSubstring11 = urlString.substring(i5, iIntValue2);
            Intrinsics.checkNotNullExpressionValue(strSubstring11, "substring(...)");
            wVar.d(strSubstring11);
            int i17 = iIntValue2 + 1;
            if (i17 < iIntValue) {
                String strSubstring12 = urlString.substring(i17, iIntValue);
                Intrinsics.checkNotNullExpressionValue(strSubstring12, "substring(...)");
                i9 = Integer.parseInt(strSubstring12);
            } else {
                i9 = 0;
            }
            wVar.e(i9);
            i5 = iIntValue;
        }
        List list = a;
        if (i5 >= i13) {
            if (urlString.charAt(length2) != '/') {
                list = K.a;
            }
            Intrinsics.checkNotNullParameter(list, "<set-?>");
            wVar.h = list;
            return;
        }
        List listI = i15 == 0 ? CollectionsKt.I(i3, wVar.h) : K.a;
        Intrinsics.checkNotNullParameter(listI, "<set-?>");
        wVar.h = listI;
        Intrinsics.checkNotNullParameter("?#", "<this>");
        char[] cArr2 = new char[2];
        for (int i18 = 0; i18 < 2; i18++) {
            cArr2[i18] = "?#".charAt(i18);
        }
        int iU2 = StringsKt__StringsKt.u(urlString, cArr2, i5, false);
        Integer numValueOf3 = Integer.valueOf(iU2);
        if (iU2 <= 0) {
            numValueOf3 = null;
        }
        int iIntValue3 = numValueOf3 != null ? numValueOf3.intValue() : i13;
        if (iIntValue3 > i5) {
            String strSubstring13 = urlString.substring(i5, iIntValue3);
            Intrinsics.checkNotNullExpressionValue(strSubstring13, "substring(...)");
            Collection collection = (wVar.h.size() == 1 && ((CharSequence) CollectionsKt.L(wVar.h)).length() == 0) ? K.a : wVar.h;
            if (Intrinsics.b(strSubstring13, "/")) {
                listV = list;
                i8 = 1;
            } else {
                i8 = 1;
                listV = StringsKt.V(strSubstring13, new char[]{'/'});
            }
            if (i15 != i8) {
                list = K.a;
            }
            ArrayList arrayListC0 = CollectionsKt.c0(collection, CollectionsKt.c0(list, listV));
            Intrinsics.checkNotNullParameter(arrayListC0, "<set-?>");
            wVar.h = arrayListC0;
            i5 = iIntValue3;
        }
        if (i5 < i13 && urlString.charAt(i5) == '?') {
            int i19 = i5 + 1;
            if (i19 == i13) {
                wVar.b = true;
                i5 = i13;
            } else {
                int i20 = 0;
                int iL2 = StringsKt.L(urlString, '#', i19, false, 4);
                Integer numValueOf4 = iL2 > 0 ? Integer.valueOf(iL2) : null;
                int iIntValue4 = numValueOf4 != null ? numValueOf4.intValue() : i13;
                String query = urlString.substring(i19, iIntValue4);
                Intrinsics.checkNotNullExpressionValue(query, "substring(...)");
                Intrinsics.checkNotNullParameter(query, "query");
                if (StringsKt.J(query) < 0) {
                    s.b.getClass();
                    vVar = f.c;
                } else {
                    j jVar = s.b;
                    u uVar = new u(13);
                    int iJ2 = StringsKt.J(query);
                    if (iJ2 >= 0) {
                        int i21 = 0;
                        int i22 = 0;
                        int i23 = 0;
                        int i24 = -1;
                        while (i21 != 1000) {
                            char cCharAt5 = query.charAt(i22);
                            if (cCharAt5 == '&') {
                                AbstractC3099a7.b(uVar, query, i23, i24, i22);
                                i21++;
                                i23 = i22 + 1;
                                i24 = -1;
                            } else if (cCharAt5 == '=' && i24 == -1) {
                                i24 = i22;
                            }
                            if (i22 != iJ2) {
                                i22++;
                            } else {
                                i6 = i24;
                                i7 = i21;
                                i20 = i23;
                            }
                        }
                        Map values = (Map) uVar.b;
                        Intrinsics.checkNotNullParameter(values, "values");
                        vVar = new v(values);
                    } else {
                        i6 = -1;
                        i7 = 0;
                    }
                    if (i7 != 1000) {
                        AbstractC3099a7.b(uVar, query, i20, i6, query.length());
                    }
                    Map values2 = (Map) uVar.b;
                    Intrinsics.checkNotNullParameter(values2, "values");
                    vVar = new v(values2);
                }
                vVar.b(new com.quizlet.features.settings.composables.dialogs.a(wVar, 22));
                i5 = iIntValue4;
            }
        }
        if (i5 >= i13 || urlString.charAt(i5) != '#') {
            return;
        }
        String strSubstring14 = urlString.substring(i5 + 1, i13);
        Intrinsics.checkNotNullExpressionValue(strSubstring14, "substring(...)");
        Intrinsics.checkNotNullParameter(strSubstring14, "<set-?>");
        wVar.g = strSubstring14;
    }
}
