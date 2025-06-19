package io.ktor.http;

import com.google.android.gms.internal.mlkit_vision_barcode.s7;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.collections.b0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import kotlin.text.D;

/* renamed from: io.ktor.http.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC4879a {
    public static final Set a;
    public static final Set b;
    public static final ArrayList c;
    public static final ArrayList d;

    static {
        ArrayList arrayListC0 = CollectionsKt.c0(CollectionsKt.e0(new kotlin.ranges.e('a', 'z'), new kotlin.ranges.e('A', 'Z')), new kotlin.ranges.e('0', '9'));
        ArrayList arrayList = new ArrayList(C.q(arrayListC0, 10));
        Iterator it2 = arrayListC0.iterator();
        while (it2.hasNext()) {
            arrayList.add(Byte.valueOf((byte) ((Character) it2.next()).charValue()));
        }
        a = CollectionsKt.A0(arrayList);
        b = CollectionsKt.A0(CollectionsKt.c0(CollectionsKt.e0(new kotlin.ranges.e('a', 'z'), new kotlin.ranges.e('A', 'Z')), new kotlin.ranges.e('0', '9')));
        CollectionsKt.A0(CollectionsKt.c0(CollectionsKt.e0(new kotlin.ranges.e('a', 'f'), new kotlin.ranges.e('A', 'F')), new kotlin.ranges.e('0', '9')));
        Character[] elements = {':', '/', '?', '#', '[', ']', '@', '!', '$', '&', '\'', '(', ')', '*', ',', ';', '=', '-', '.', '_', '~', '+'};
        Intrinsics.checkNotNullParameter(elements, "elements");
        Set setT = C4933y.T(elements);
        ArrayList arrayList2 = new ArrayList(C.q(setT, 10));
        Iterator it3 = setT.iterator();
        while (it3.hasNext()) {
            arrayList2.add(Byte.valueOf((byte) ((Character) it3.next()).charValue()));
        }
        c = arrayList2;
        Character[] elements2 = {':', '@', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', '-', '.', '_', '~'};
        Intrinsics.checkNotNullParameter(elements2, "elements");
        C4933y.T(elements2);
        Set set = b;
        Character[] elements3 = {'!', '#', '$', '&', '+', '-', '.', '^', '_', '`', '|', '~'};
        Intrinsics.checkNotNullParameter(elements3, "elements");
        b0.f(set, C4933y.T(elements3));
        List listJ = B.j('-', '.', '_', '~');
        ArrayList arrayList3 = new ArrayList(C.q(listJ, 10));
        Iterator it4 = listJ.iterator();
        while (it4.hasNext()) {
            arrayList3.add(Byte.valueOf((byte) ((Character) it4.next()).charValue()));
        }
        d = arrayList3;
    }

    public static final int a(char c2) {
        if ('0' <= c2 && c2 < ':') {
            return c2 - '0';
        }
        if ('A' <= c2 && c2 < 'G') {
            return c2 - '7';
        }
        if ('a' > c2 || c2 >= 'g') {
            return -1;
        }
        return c2 - 'W';
    }

    public static final String b(int i, int i2, String str, boolean z) throws URLDecodeException {
        int i3 = i;
        while (i3 < i2) {
            char cCharAt = str.charAt(i3);
            if (cCharAt == '%' || (z && cCharAt == '+')) {
                int i4 = i2 - i;
                if (i4 > 255) {
                    i4 /= 3;
                }
                StringBuilder sb = new StringBuilder(i4);
                if (i3 > i) {
                    sb.append((CharSequence) str, i, i3);
                }
                byte[] bArr = null;
                while (i3 < i2) {
                    char cCharAt2 = str.charAt(i3);
                    if (z && cCharAt2 == '+') {
                        sb.append(' ');
                    } else if (cCharAt2 == '%') {
                        if (bArr == null) {
                            bArr = new byte[(i2 - i3) / 3];
                        }
                        int i5 = 0;
                        while (i3 < i2 && str.charAt(i3) == '%') {
                            int i6 = i3 + 2;
                            if (i6 >= i2) {
                                throw new URLDecodeException("Incomplete trailing HEX escape: " + str.subSequence(i3, str.length()).toString() + ", in " + ((Object) str) + " at " + i3);
                            }
                            int i7 = i3 + 1;
                            int iA = a(str.charAt(i7));
                            int iA2 = a(str.charAt(i6));
                            if (iA == -1 || iA2 == -1) {
                                throw new URLDecodeException("Wrong HEX escape: %" + str.charAt(i7) + str.charAt(i6) + ", in " + ((Object) str) + ", at " + i3);
                            }
                            bArr[i5] = (byte) ((iA * 16) + iA2);
                            i3 += 3;
                            i5++;
                        }
                        sb.append(D.j(i5, bArr, 4));
                    } else {
                        sb.append(cCharAt2);
                    }
                    i3++;
                }
                String string = sb.toString();
                Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                return string;
            }
            i3++;
        }
        if (i == 0 && i2 == str.length()) {
            return str.toString();
        }
        String strSubstring = str.substring(i, i2);
        Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
        return strSubstring;
    }

    public static String c(String str) {
        int length = str.length();
        Charset charset = Charsets.UTF_8;
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter(charset, "charset");
        return b(0, length, str, false);
    }

    public static String d(int i, int i2, String str, int i3) {
        if ((i3 & 1) != 0) {
            i = 0;
        }
        if ((i3 & 2) != 0) {
            i2 = str.length();
        }
        boolean z = (i3 & 4) == 0;
        Charset charset = Charsets.UTF_8;
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter(charset, "charset");
        return b(i, i2, str, z);
    }

    public static final String e(String input, boolean z) {
        Intrinsics.checkNotNullParameter(input, "<this>");
        StringBuilder sb = new StringBuilder();
        CharsetEncoder charsetEncoderNewEncoder = Charsets.UTF_8.newEncoder();
        Intrinsics.checkNotNullExpressionValue(charsetEncoderNewEncoder, "newEncoder(...)");
        int length = input.length();
        Intrinsics.checkNotNullParameter(charsetEncoderNewEncoder, "<this>");
        Intrinsics.checkNotNullParameter(input, "input");
        kotlinx.io.a dst = new kotlinx.io.a();
        Intrinsics.checkNotNullParameter(charsetEncoderNewEncoder, "<this>");
        Intrinsics.checkNotNullParameter(dst, "destination");
        Intrinsics.checkNotNullParameter(input, "input");
        if (length > 0) {
            int i = 0;
            do {
                Intrinsics.checkNotNullParameter(charsetEncoderNewEncoder, "<this>");
                Intrinsics.checkNotNullParameter(input, "input");
                Intrinsics.checkNotNullParameter(dst, "dst");
                byte[] bArrC = s7.c(charsetEncoderNewEncoder, input, i, length);
                dst.j(bArrC.length, bArrC);
                int length2 = bArrC.length;
                if (length2 < 0) {
                    throw new IllegalStateException("Check failed.");
                }
                i += length2;
            } while (i < length);
        }
        f(dst, new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.i(z, 2, sb));
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }

    public static final void f(kotlinx.io.a aVar, Function1 function1) {
        com.sdk.growthbook.features.b block = new com.sdk.growthbook.features.b(2, function1);
        Intrinsics.checkNotNullParameter(aVar, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        while (!aVar.u()) {
            block.invoke(aVar);
        }
    }

    public static final String g(byte b2) {
        int i = (b2 & 255) >> 4;
        int i2 = b2 & 15;
        char[] cArr = {'%', (char) ((i < 0 || i >= 10) ? ((char) (i + 65)) - '\n' : i + 48), (char) ((i2 < 0 || i2 >= 10) ? ((char) (i2 + 65)) - '\n' : i2 + 48)};
        Intrinsics.checkNotNullParameter(cArr, "<this>");
        return new String(cArr);
    }
}
