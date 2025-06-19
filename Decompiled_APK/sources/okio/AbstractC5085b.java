package okio;

import androidx.compose.animation.d0;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.ArrayList;
import java.util.logging.Logger;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* renamed from: okio.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC5085b {
    public static final boolean a(int i, int i2, int i3, byte[] a, byte[] b) {
        Intrinsics.checkNotNullParameter(a, "a");
        Intrinsics.checkNotNullParameter(b, "b");
        for (int i4 = 0; i4 < i3; i4++) {
            if (a[i4 + i] != b[i4 + i2]) {
                return false;
            }
        }
        return true;
    }

    public static final z b(E e) {
        Intrinsics.checkNotNullParameter(e, "<this>");
        return new z(e);
    }

    public static final A c(G g) {
        Intrinsics.checkNotNullParameter(g, "<this>");
        return new A(g);
    }

    public static void d(long j, C5091h c5091h, int i, ArrayList arrayList, int i2, int i3, ArrayList arrayList2) {
        int i4;
        int i5;
        ArrayList arrayList3;
        long j2;
        int i6;
        int i7 = i;
        ArrayList arrayList4 = arrayList;
        ArrayList arrayList5 = arrayList2;
        if (i2 >= i3) {
            throw new IllegalArgumentException("Failed requirement.");
        }
        for (int i8 = i2; i8 < i3; i8++) {
            if (((k) arrayList4.get(i8)).d() < i7) {
                throw new IllegalArgumentException("Failed requirement.");
            }
        }
        k kVar = (k) arrayList.get(i2);
        k kVar2 = (k) arrayList4.get(i3 - 1);
        if (i7 == kVar.d()) {
            int iIntValue = ((Number) arrayList5.get(i2)).intValue();
            int i9 = i2 + 1;
            k kVar3 = (k) arrayList4.get(i9);
            i4 = i9;
            i5 = iIntValue;
            kVar = kVar3;
        } else {
            i4 = i2;
            i5 = -1;
        }
        if (kVar.j(i7) == kVar2.j(i7)) {
            int iMin = Math.min(kVar.d(), kVar2.d());
            int i10 = 0;
            for (int i11 = i7; i11 < iMin && kVar.j(i11) == kVar2.j(i11); i11++) {
                i10++;
            }
            long j3 = 4;
            long j4 = (c5091h.b / j3) + j + 2 + i10 + 1;
            c5091h.s0(-i10);
            c5091h.s0(i5);
            int i12 = i7 + i10;
            while (i7 < i12) {
                c5091h.s0(kVar.j(i7) & 255);
                i7++;
            }
            if (i4 + 1 == i3) {
                if (i12 != ((k) arrayList4.get(i4)).d()) {
                    throw new IllegalStateException("Check failed.");
                }
                c5091h.s0(((Number) arrayList5.get(i4)).intValue());
                return;
            } else {
                C5091h c5091h2 = new C5091h();
                c5091h.s0(((int) ((c5091h2.b / j3) + j4)) * (-1));
                d(j4, c5091h2, i12, arrayList4, i4, i3, arrayList5);
                c5091h.M(c5091h2);
                return;
            }
        }
        int i13 = 1;
        for (int i14 = i4 + 1; i14 < i3; i14++) {
            if (((k) arrayList4.get(i14 - 1)).j(i7) != ((k) arrayList4.get(i14)).j(i7)) {
                i13++;
            }
        }
        long j5 = 4;
        long j6 = (c5091h.b / j5) + j + 2 + (i13 * 2);
        c5091h.s0(i13);
        c5091h.s0(i5);
        for (int i15 = i4; i15 < i3; i15++) {
            int iJ = ((k) arrayList4.get(i15)).j(i7);
            if (i15 == i4 || iJ != ((k) arrayList4.get(i15 - 1)).j(i7)) {
                c5091h.s0(iJ & 255);
            }
        }
        C5091h c5091h3 = new C5091h();
        int i16 = i4;
        while (i16 < i3) {
            byte bJ = ((k) arrayList4.get(i16)).j(i7);
            int i17 = i16 + 1;
            int i18 = i17;
            while (true) {
                if (i18 >= i3) {
                    i18 = i3;
                    break;
                } else if (bJ != ((k) arrayList4.get(i18)).j(i7)) {
                    break;
                } else {
                    i18++;
                }
            }
            if (i17 == i18 && i7 + 1 == ((k) arrayList4.get(i16)).d()) {
                c5091h.s0(((Number) arrayList5.get(i16)).intValue());
                arrayList3 = arrayList5;
                j2 = j6;
                i6 = i18;
            } else {
                c5091h.s0(((int) ((c5091h3.b / j5) + j6)) * (-1));
                arrayList3 = arrayList5;
                j2 = j6;
                i6 = i18;
                d(j2, c5091h3, i7 + 1, arrayList, i16, i6, arrayList3);
                arrayList4 = arrayList;
            }
            j6 = j2;
            i16 = i6;
            arrayList5 = arrayList3;
        }
        c5091h.M(c5091h3);
    }

    public static final void e(long j, long j2, long j3) {
        if ((j2 | j3) < 0 || j2 > j || j - j2 < j3) {
            StringBuilder sbT = d0.t(j, "size=", " offset=");
            sbT.append(j2);
            sbT.append(" byteCount=");
            sbT.append(j3);
            throw new ArrayIndexOutOfBoundsException(sbT.toString());
        }
    }

    public static final boolean f(AssertionError assertionError) {
        Logger logger = v.a;
        Intrinsics.checkNotNullParameter(assertionError, "<this>");
        if (assertionError.getCause() != null) {
            String message = assertionError.getMessage();
            if (message != null ? StringsKt.G(message, "getsockname failed", false) : false) {
                return true;
            }
        }
        return false;
    }

    /* JADX WARN: Code restructure failed: missing block: B:43:0x00cd, code lost:
    
        continue;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static okio.w g(okio.k... r11) {
        /*
            Method dump skipped, instructions count: 268
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: okio.AbstractC5085b.g(okio.k[]):okio.w");
    }

    public static final C5086c h(Socket socket) throws IOException {
        Logger logger = v.a;
        Intrinsics.checkNotNullParameter(socket, "<this>");
        F f = new F(socket);
        OutputStream outputStream = socket.getOutputStream();
        Intrinsics.checkNotNullExpressionValue(outputStream, "getOutputStream(...)");
        C5086c sink = new C5086c(outputStream, f);
        Intrinsics.checkNotNullParameter(sink, "sink");
        return new C5086c(f, sink);
    }

    public static final C5087d i(File file) {
        Logger logger = v.a;
        Intrinsics.checkNotNullParameter(file, "<this>");
        return new C5087d(new FileInputStream(file), I.d);
    }

    public static final C5087d j(InputStream inputStream) {
        Logger logger = v.a;
        Intrinsics.checkNotNullParameter(inputStream, "<this>");
        return new C5087d(inputStream, new I());
    }

    public static final C5087d k(Socket socket) throws IOException {
        Logger logger = v.a;
        Intrinsics.checkNotNullParameter(socket, "<this>");
        F f = new F(socket);
        InputStream inputStream = socket.getInputStream();
        Intrinsics.checkNotNullExpressionValue(inputStream, "getInputStream(...)");
        C5087d source = new C5087d(inputStream, f);
        Intrinsics.checkNotNullParameter(source, "source");
        return new C5087d(f, source);
    }

    public static final String l(int i) {
        int i2 = 0;
        if (i == 0) {
            return "0";
        }
        char[] cArr = okio.internal.b.a;
        char[] cArr2 = {cArr[(i >> 28) & 15], cArr[(i >> 24) & 15], cArr[(i >> 20) & 15], cArr[(i >> 16) & 15], cArr[(i >> 12) & 15], cArr[(i >> 8) & 15], cArr[(i >> 4) & 15], cArr[i & 15]};
        while (i2 < 8 && cArr2[i2] == '0') {
            i2++;
        }
        return kotlin.text.D.h(cArr2, i2, 8);
    }
}
