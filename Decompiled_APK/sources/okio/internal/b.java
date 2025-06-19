package okio.internal;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.collections.V;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.F;
import kotlin.jvm.internal.I;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;
import kotlin.text.CharsKt;
import kotlin.text.D;
import kotlin.text.StringsKt;
import okio.A;
import okio.C5091h;
import okio.x;

/* loaded from: classes3.dex */
public abstract class b {
    public static final char[] a = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    public static final int a(char c) {
        if ('0' <= c && c < ':') {
            return c - '0';
        }
        if ('a' <= c && c < 'g') {
            return c - 'W';
        }
        if ('A' <= c && c < 'G') {
            return c - '7';
        }
        throw new IllegalArgumentException("Unexpected hex digit: " + c);
    }

    public static final LinkedHashMap b(ArrayList arrayList) {
        String str = x.b;
        x xVarF = com.quizlet.quizletandroid.ui.folder.logging.a.f("/", false);
        LinkedHashMap linkedHashMapG = V.g(new Pair(xVarF, new h(xVarF, true, null, 0L, 0L, 0L, 0, 0L, 0, 0, null, null, null, 65532)));
        for (h hVar : CollectionsKt.n0(arrayList, new com.google.zxing.aztec.encoder.c(25))) {
            if (((h) linkedHashMapG.put(hVar.a, hVar)) == null) {
                while (true) {
                    x xVar = hVar.a;
                    x xVarC = xVar.c();
                    if (xVarC != null) {
                        h hVar2 = (h) linkedHashMapG.get(xVarC);
                        if (hVar2 != null) {
                            hVar2.q.add(xVar);
                            break;
                        }
                        h hVar3 = new h(xVarC, true, null, 0L, 0L, 0L, 0, 0L, 0, 0, null, null, null, 65532);
                        linkedHashMapG.put(xVarC, hVar3);
                        hVar3.q.add(xVar);
                        hVar = hVar3;
                    }
                }
            }
        }
        return linkedHashMapG;
    }

    /* JADX WARN: Removed duplicated region for block: B:45:0x00d7 A[Catch: all -> 0x00fe, TRY_LEAVE, TryCatch #2 {all -> 0x00fe, blocks: (B:43:0x00d1, B:45:0x00d7), top: B:67:0x00d1 }] */
    /* JADX WARN: Removed duplicated region for block: B:59:0x0119  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x012c  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x001c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object c(kotlin.sequences.i r18, okio.n r19, kotlin.collections.C4927s r20, okio.x r21, boolean r22, kotlin.coroutines.jvm.internal.a r23) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 303
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: okio.internal.b.c(kotlin.sequences.i, okio.n, kotlin.collections.s, okio.x, boolean, kotlin.coroutines.jvm.internal.a):java.lang.Object");
    }

    public static final String d(int i) {
        StringBuilder sb = new StringBuilder("0x");
        String string = Integer.toString(i, CharsKt.checkRadix(16));
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        sb.append(string);
        return sb.toString();
    }

    /* JADX WARN: Code restructure failed: missing block: B:100:0x01d1, code lost:
    
        return r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:101:0x01d2, code lost:
    
        throw r9;
     */
    /* JADX WARN: Code restructure failed: missing block: B:106:0x01db, code lost:
    
        throw new java.io.IOException("unsupported zip: spanned");
     */
    /* JADX WARN: Code restructure failed: missing block: B:11:0x0060, code lost:
    
        if (r14 != (r11.q() & 65535)) goto L104;
     */
    /* JADX WARN: Code restructure failed: missing block: B:12:0x0062, code lost:
    
        if (r0 != 0) goto L104;
     */
    /* JADX WARN: Code restructure failed: missing block: B:13:0x0064, code lost:
    
        if (r10 != 0) goto L104;
     */
    /* JADX WARN: Code restructure failed: missing block: B:14:0x0066, code lost:
    
        r19 = r7;
     */
    /* JADX WARN: Code restructure failed: missing block: B:15:0x006a, code lost:
    
        r11.skip(4);
        r18 = r11.q() & 65535;
        r13 = new com.google.android.gms.internal.ads.C2679u(r14, r11.j() & 4294967295L, r18);
        r11.r(r18);
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x008b, code lost:
    
        r11.close();
        r5 = r5 - 20;
        r9 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:17:0x0095, code lost:
    
        if (r5 <= r19) goto L73;
     */
    /* JADX WARN: Code restructure failed: missing block: B:18:0x0097, code lost:
    
        r5 = okio.AbstractC5085b.c(r4.f(r5));
     */
    /* JADX WARN: Code restructure failed: missing block: B:20:0x00a6, code lost:
    
        if (r5.j() != 117853008) goto L58;
     */
    /* JADX WARN: Code restructure failed: missing block: B:21:0x00a8, code lost:
    
        r6 = r5.j();
        r10 = r5.l();
     */
    /* JADX WARN: Code restructure failed: missing block: B:22:0x00b5, code lost:
    
        if (r5.j() != 1) goto L56;
     */
    /* JADX WARN: Code restructure failed: missing block: B:23:0x00b7, code lost:
    
        if (r6 != 0) goto L56;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x00b9, code lost:
    
        r6 = okio.AbstractC5085b.c(r4.f(r10));
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x00c1, code lost:
    
        r8 = r6.j();
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x00c8, code lost:
    
        if (r8 != 101075792) goto L42;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x00ca, code lost:
    
        r6.skip(12);
        r8 = r6.j();
        r10 = r6.j();
        r22 = r6.l();
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x00e1, code lost:
    
        if (r22 != r6.l()) goto L39;
     */
    /* JADX WARN: Code restructure failed: missing block: B:29:0x00e3, code lost:
    
        if (r8 != 0) goto L39;
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x00e5, code lost:
    
        if (r10 != 0) goto L39;
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x00e7, code lost:
    
        r6.skip(8);
        r21 = new com.google.android.gms.internal.ads.C2679u(r22, r6.l(), r18);
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x00f7, code lost:
    
        r0 = kotlin.Unit.a;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x00fc, code lost:
    
        r0 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x00fe, code lost:
    
        r0 = th;
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x0102, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x0103, code lost:
    
        r7 = r0;
        r13 = r21;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x010c, code lost:
    
        throw new java.io.IOException("unsupported zip: spanned");
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x010d, code lost:
    
        r7 = r0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x0135, code lost:
    
        throw new java.io.IOException("bad zip: expected " + d(101075792) + " but was " + d(r8));
     */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x0136, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x0138, code lost:
    
        r6.close();
        r0 = kotlin.Unit.a;
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x013e, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:49:0x013f, code lost:
    
        kotlin.C4937f.a(r7, r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x0142, code lost:
    
        r0 = r7;
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x0146, code lost:
    
        throw r0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x0147, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x014f, code lost:
    
        throw new java.io.IOException("unsupported zip: spanned");
     */
    /* JADX WARN: Code restructure failed: missing block: B:58:0x0150, code lost:
    
        r0 = kotlin.Unit.a;
     */
    /* JADX WARN: Code restructure failed: missing block: B:60:0x0155, code lost:
    
        r0 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:61:0x0157, code lost:
    
        r0 = th;
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x0159, code lost:
    
        r5.close();
        r0 = kotlin.Unit.a;
     */
    /* JADX WARN: Code restructure failed: missing block: B:65:0x015f, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:66:0x0160, code lost:
    
        kotlin.C4937f.a(r0, r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:67:0x0163, code lost:
    
        r0 = r0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:68:0x0164, code lost:
    
        if (r0 == null) goto L69;
     */
    /* JADX WARN: Code restructure failed: missing block: B:70:0x0167, code lost:
    
        throw r0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:73:0x016c, code lost:
    
        r5 = new java.util.ArrayList();
        r6 = okio.AbstractC5085b.c(r4.f(r13.b));
     */
    /* JADX WARN: Code restructure failed: missing block: B:74:0x017b, code lost:
    
        r7 = r13.a;
     */
    /* JADX WARN: Code restructure failed: missing block: B:77:0x0181, code lost:
    
        r0 = f(r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:78:0x018b, code lost:
    
        if (r0.h < r13.b) goto L79;
     */
    /* JADX WARN: Code restructure failed: missing block: B:80:0x0197, code lost:
    
        if (((java.lang.Boolean) r29.invoke(r0)).booleanValue() != false) goto L81;
     */
    /* JADX WARN: Code restructure failed: missing block: B:81:0x0199, code lost:
    
        r5.add(r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:82:0x019d, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:84:0x01a0, code lost:
    
        r19 = r19 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:86:0x01ac, code lost:
    
        throw new java.io.IOException("bad zip: local file header offset >= central directory offset");
     */
    /* JADX WARN: Code restructure failed: missing block: B:87:0x01ad, code lost:
    
        r0 = kotlin.Unit.a;
     */
    /* JADX WARN: Code restructure failed: missing block: B:90:0x01b3, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:91:0x01b4, code lost:
    
        r9 = r0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:92:0x01b6, code lost:
    
        r6.close();
        r0 = kotlin.Unit.a;
     */
    /* JADX WARN: Code restructure failed: missing block: B:94:0x01bc, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:95:0x01bd, code lost:
    
        kotlin.C4937f.a(r0, r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:96:0x01c0, code lost:
    
        r9 = r0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:97:0x01c1, code lost:
    
        if (r9 == null) goto L98;
     */
    /* JADX WARN: Code restructure failed: missing block: B:98:0x01c3, code lost:
    
        r3 = new okio.J(r27, r28, b(r5));
     */
    /* JADX WARN: Code restructure failed: missing block: B:99:0x01cc, code lost:
    
        r4.close();
        r0 = kotlin.Unit.a;
     */
    /* JADX WARN: Code restructure failed: missing block: B:9:0x0043, code lost:
    
        r0 = r11.q() & 65535;
        r10 = r11.q() & 65535;
        r14 = r11.q() & 65535;
     */
    /* JADX WARN: Removed duplicated region for block: B:52:0x0145  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0146 A[Catch: all -> 0x0147, TryCatch #1 {all -> 0x0147, blocks: (B:19:0x009f, B:21:0x00a8, B:24:0x00b9, B:53:0x0146, B:49:0x013f, B:56:0x014a, B:57:0x014f, B:58:0x0150, B:46:0x0138), top: B:126:0x009f, outer: #2, inners: #11 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final okio.J e(okio.x r27, okio.n r28, kotlin.jvm.functions.Function1 r29) {
        /*
            Method dump skipped, instructions count: 539
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: okio.internal.b.e(okio.x, okio.n, kotlin.jvm.functions.Function1):okio.J");
    }

    public static final h f(final A a2) throws IOException {
        Intrinsics.checkNotNullParameter(a2, "<this>");
        int iJ = a2.j();
        if (iJ != 33639248) {
            throw new IOException("bad zip: expected " + d(33639248) + " but was " + d(iJ));
        }
        a2.skip(4L);
        short sQ = a2.q();
        int i = sQ & 65535;
        if ((sQ & 1) != 0) {
            throw new IOException("unsupported zip: general purpose bit flag=" + d(i));
        }
        int iQ = a2.q() & 65535;
        int iQ2 = a2.q() & 65535;
        int iQ3 = a2.q() & 65535;
        long j = a2.j() & 4294967295L;
        final I i2 = new I();
        i2.a = a2.j() & 4294967295L;
        final I i3 = new I();
        i3.a = a2.j() & 4294967295L;
        int iQ4 = a2.q() & 65535;
        int iQ5 = a2.q() & 65535;
        int iQ6 = 65535 & a2.q();
        a2.skip(8L);
        final I i4 = new I();
        i4.a = a2.j() & 4294967295L;
        String strR = a2.r(iQ4);
        if (StringsKt.F(strR, (char) 0, false)) {
            throw new IOException("bad zip: filename contains 0x00");
        }
        final long j2 = i3.a == 4294967295L ? 8 : 0L;
        if (i2.a == 4294967295L) {
            j2 += 8;
        }
        if (i4.a == 4294967295L) {
            j2 += 8;
        }
        final J j3 = new J();
        final J j4 = new J();
        final J j5 = new J();
        final F f = new F();
        g(a2, iQ5, new Function2() { // from class: okio.internal.j
            @Override // kotlin.jvm.functions.Function2
            public final Object invoke(Object obj, Object obj2) throws IOException {
                int iIntValue = ((Integer) obj).intValue();
                long jLongValue = ((Long) obj2).longValue();
                A a3 = a2;
                if (iIntValue == 1) {
                    F f2 = f;
                    if (f2.a) {
                        throw new IOException("bad zip: zip64 extra repeated");
                    }
                    f2.a = true;
                    if (jLongValue < j2) {
                        throw new IOException("bad zip: zip64 extra too short");
                    }
                    I i5 = i3;
                    long jL = i5.a;
                    if (jL == 4294967295L) {
                        jL = a3.l();
                    }
                    i5.a = jL;
                    I i6 = i2;
                    i6.a = i6.a == 4294967295L ? a3.l() : 0L;
                    I i7 = i4;
                    i7.a = i7.a == 4294967295L ? a3.l() : 0L;
                } else if (iIntValue == 10) {
                    if (jLongValue < 4) {
                        throw new IOException("bad zip: NTFS extra too short");
                    }
                    a3.skip(4L);
                    b.g(a3, (int) (jLongValue - 4), new i(j3, a3, j4, j5));
                }
                return Unit.a;
            }
        });
        if (j2 > 0 && !f.a) {
            throw new IOException("bad zip: zip64 extra required but absent");
        }
        String strR2 = a2.r(iQ6);
        String str = x.b;
        return new h(com.quizlet.quizletandroid.ui.folder.logging.a.f("/", false).e(strR), D.k(strR, "/", false), strR2, j, i2.a, i3.a, iQ, i4.a, iQ3, iQ2, (Long) j3.a, (Long) j4.a, (Long) j5.a, 57344);
    }

    public static final void g(A a2, int i, Function2 function2) throws IOException {
        long j = i;
        while (j != 0) {
            if (j < 4) {
                throw new IOException("bad zip: truncated header in extra field");
            }
            int iQ = a2.q() & 65535;
            long jQ = a2.q() & 65535;
            long j2 = j - 4;
            if (j2 < jQ) {
                throw new IOException("bad zip: truncated value in extra field");
            }
            a2.k(jQ);
            C5091h c5091h = a2.b;
            long j3 = c5091h.b;
            function2.invoke(Integer.valueOf(iQ), Long.valueOf(jQ));
            long j4 = (c5091h.b + jQ) - j3;
            if (j4 < 0) {
                throw new IOException(android.support.v4.media.session.a.f(iQ, "unsupported zip: too many bytes processed for "));
            }
            if (j4 > 0) {
                c5091h.skip(j4);
            }
            j = j2 - jQ;
        }
    }

    public static final h h(A a2, h hVar) throws IOException {
        int iJ = a2.j();
        if (iJ != 67324752) {
            throw new IOException("bad zip: expected " + d(67324752) + " but was " + d(iJ));
        }
        a2.skip(2L);
        short sQ = a2.q();
        int i = sQ & 65535;
        if ((sQ & 1) != 0) {
            throw new IOException("unsupported zip: general purpose bit flag=" + d(i));
        }
        a2.skip(18L);
        int iQ = a2.q() & 65535;
        a2.skip(a2.q() & 65535);
        if (hVar == null) {
            a2.skip(iQ);
            return null;
        }
        J j = new J();
        J j2 = new J();
        J j3 = new J();
        g(a2, iQ, new i(a2, j, j2, j3));
        return new h(hVar.a, hVar.b, hVar.c, hVar.d, hVar.e, hVar.f, hVar.g, hVar.h, hVar.i, hVar.j, hVar.k, hVar.l, hVar.m, (Integer) j.a, (Integer) j2.a, (Integer) j3.a);
    }

    public static final int i(okio.D d, int i) {
        int i2;
        Intrinsics.checkNotNullParameter(d, "<this>");
        int[] iArr = d.f;
        int i3 = i + 1;
        int length = d.e.length;
        Intrinsics.checkNotNullParameter(iArr, "<this>");
        int i4 = length - 1;
        int i5 = 0;
        while (true) {
            if (i5 <= i4) {
                i2 = (i5 + i4) >>> 1;
                int i6 = iArr[i2];
                if (i6 >= i3) {
                    if (i6 <= i3) {
                        break;
                    }
                    i4 = i2 - 1;
                } else {
                    i5 = i2 + 1;
                }
            } else {
                i2 = (-i5) - 1;
                break;
            }
        }
        return i2 >= 0 ? i2 : ~i2;
    }
}
