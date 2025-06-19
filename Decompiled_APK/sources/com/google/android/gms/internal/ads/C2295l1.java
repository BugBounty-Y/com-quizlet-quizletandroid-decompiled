package com.google.android.gms.internal.ads;

import android.util.SparseArray;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.io.EOFException;
import java.io.InterruptedIOException;
import java.math.RoundingMode;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/* renamed from: com.google.android.gms.internal.ads.l1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2295l1 implements U {
    public static final byte[] f0 = {49, 10, 48, 48, 58, 48, 48, 58, 48, 48, 44, 48, 48, 48, 32, 45, 45, 62, 32, 48, 48, 58, 48, 48, 58, 48, 48, 44, 48, 48, 48, 10};
    public static final byte[] g0;
    public static final byte[] h0;
    public static final byte[] i0;
    public static final UUID j0;
    public static final Map k0;
    public boolean A;
    public long B;
    public long C;
    public long D;
    public androidx.compose.ui.input.pointer.util.b E;
    public androidx.compose.ui.input.pointer.util.b F;
    public boolean G;
    public boolean H;
    public int I;
    public long J;
    public long K;
    public int L;
    public int M;
    public int[] N;
    public int O;
    public int P;
    public int Q;
    public int R;
    public boolean S;
    public long T;
    public int U;
    public int V;
    public int W;
    public boolean X;
    public boolean Y;
    public boolean Z;
    public final C2338m1 a;
    public int a0;
    public final SparseArray b;
    public byte b0;
    public final boolean c;
    public boolean c0;
    public final boolean d;
    public W d0;
    public final Z1 e;
    public final C2209j1 e0;
    public final Kn f;
    public final Kn g;
    public final Kn h;
    public final Kn i;
    public final Kn j;
    public final Kn k;
    public final Kn l;
    public final Kn m;
    public final Kn n;
    public final Kn o;
    public ByteBuffer p;
    public long q;
    public long r;
    public long s;
    public long t;
    public long u;
    public boolean v;
    public C2252k1 w;
    public boolean x;
    public int y;
    public long z;

    static {
        String str = Yo.a;
        g0 = "Format: Start, End, ReadOrder, Layer, Style, Name, MarginL, MarginR, MarginV, Effect, Text".getBytes(StandardCharsets.UTF_8);
        h0 = new byte[]{68, 105, 97, 108, 111, 103, 117, 101, 58, 32, 48, 58, 48, 48, 58, 48, 48, 58, 48, 48, 44, 48, 58, 48, 48, 58, 48, 48, 58, 48, 48, 44};
        i0 = new byte[]{87, 69, 66, 86, 84, 84, 10, 10, 48, 48, 58, 48, 48, 58, 48, 48, 46, 48, 48, 48, 32, 45, 45, 62, 32, 48, 48, 58, 48, 48, 58, 48, 48, 46, 48, 48, 48, 10};
        j0 = new UUID(72057594037932032L, -9223371306706625679L);
        HashMap map = new HashMap();
        androidx.compose.ui.node.B.r(0, map, "htc_video_rotA-000", 90, "htc_video_rotA-090");
        androidx.compose.ui.node.B.r(SubsamplingScaleImageView.ORIENTATION_180, map, "htc_video_rotA-180", SubsamplingScaleImageView.ORIENTATION_270, "htc_video_rotA-270");
        k0 = Collections.unmodifiableMap(map);
    }

    public C2295l1() {
        this(new C2209j1(), 2, Z1.P0);
    }

    public static byte[] o(long j, long j2, String str) {
        AbstractC1795We.B(j != -9223372036854775807L);
        Locale locale = Locale.US;
        int i = (int) (j / 3600000000L);
        Integer numValueOf = Integer.valueOf(i);
        long j3 = j - (i * 3600000000L);
        int i2 = (int) (j3 / 60000000);
        Integer numValueOf2 = Integer.valueOf(i2);
        long j4 = j3 - (i2 * 60000000);
        int i3 = (int) (j4 / 1000000);
        String str2 = String.format(locale, str, numValueOf, numValueOf2, Integer.valueOf(i3), Integer.valueOf((int) ((j4 - (i3 * 1000000)) / j2)));
        String str3 = Yo.a;
        return str2.getBytes(StandardCharsets.UTF_8);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:193:0x031c  */
    /* JADX WARN: Removed duplicated region for block: B:298:0x0498  */
    /* JADX WARN: Removed duplicated region for block: B:461:0x080c  */
    /* JADX WARN: Removed duplicated region for block: B:466:0x0824  */
    /* JADX WARN: Removed duplicated region for block: B:467:0x0826  */
    /* JADX WARN: Removed duplicated region for block: B:470:0x0833  */
    /* JADX WARN: Removed duplicated region for block: B:471:0x0840  */
    /* JADX WARN: Removed duplicated region for block: B:558:0x0a0a  */
    /* JADX WARN: Removed duplicated region for block: B:563:0x0a1e  */
    /* JADX WARN: Removed duplicated region for block: B:564:0x0a21  */
    /* JADX WARN: Type inference failed for: r1v5, types: [com.google.android.gms.internal.ads.k1, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r1v8 */
    /* JADX WARN: Type inference failed for: r1v9, types: [java.lang.RuntimeException] */
    /* JADX WARN: Type inference failed for: r5v73 */
    /* JADX WARN: Type inference failed for: r5v74, types: [java.lang.RuntimeException] */
    /* JADX WARN: Type inference failed for: r5v76, types: [int] */
    /* JADX WARN: Type inference failed for: r5v77 */
    /* JADX WARN: Type inference failed for: r5v82 */
    /* JADX WARN: Type inference failed for: r5v84 */
    /* JADX WARN: Type inference failed for: r5v87 */
    /* JADX WARN: Type inference failed for: r5v88 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(int r45) throws com.google.android.gms.internal.ads.zzaz {
        /*
            Method dump skipped, instructions count: 3194
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2295l1.a(int):void");
    }

    public final int b(P p, C2252k1 c2252k1, int i, boolean z) throws zzaz, EOFException, InterruptedIOException {
        int iD;
        int iD2;
        int i2;
        if ("S_TEXT/UTF8".equals(c2252k1.c)) {
            n(p, f0, i);
            int i3 = this.V;
            m();
            return i3;
        }
        if ("S_TEXT/ASS".equals(c2252k1.c)) {
            n(p, h0, i);
            int i4 = this.V;
            m();
            return i4;
        }
        if ("S_TEXT/WEBVTT".equals(c2252k1.c)) {
            n(p, i0, i);
            int i5 = this.V;
            m();
            return i5;
        }
        InterfaceC2380n0 interfaceC2380n0 = c2252k1.Z;
        boolean z2 = this.X;
        Kn kn = this.k;
        if (!z2) {
            boolean z3 = c2252k1.i;
            Kn kn2 = this.h;
            if (z3) {
                this.Q &= -1073741825;
                if (!this.Y) {
                    p.h(kn2.a, 0, 1, false);
                    this.U++;
                    byte b = kn2.a[0];
                    if ((b & 128) == 128) {
                        throw zzaz.a(null, "Extension bit is set in signal byte");
                    }
                    this.b0 = b;
                    this.Y = true;
                }
                byte b2 = this.b0;
                if ((b2 & 1) == 1) {
                    int i6 = b2 & 2;
                    this.Q |= 1073741824;
                    if (!this.c0) {
                        Kn kn3 = this.m;
                        p.h(kn3.a, 0, 8, false);
                        this.U += 8;
                        this.c0 = true;
                        kn2.a[0] = (byte) ((i6 != 2 ? 0 : 128) | 8);
                        kn2.j(0);
                        interfaceC2380n0.b(kn2, 1, 1);
                        this.V++;
                        kn3.j(0);
                        interfaceC2380n0.b(kn3, 8, 1);
                        this.V += 8;
                    }
                    if (i6 == 2) {
                        if (!this.Z) {
                            p.h(kn2.a, 0, 1, false);
                            this.U++;
                            kn2.j(0);
                            this.a0 = kn2.z();
                            this.Z = true;
                        }
                        int i7 = this.a0 * 4;
                        kn2.g(i7);
                        p.h(kn2.a, 0, i7, false);
                        this.U += i7;
                        int i8 = (this.a0 >> 1) + 1;
                        int i9 = (i8 * 6) + 2;
                        ByteBuffer byteBuffer = this.p;
                        if (byteBuffer == null || byteBuffer.capacity() < i9) {
                            this.p = ByteBuffer.allocate(i9);
                        }
                        this.p.position(0);
                        this.p.putShort((short) i8);
                        int i10 = 0;
                        int i11 = 0;
                        while (true) {
                            i2 = this.a0;
                            if (i10 >= i2) {
                                break;
                            }
                            int iC = kn2.C();
                            int i12 = iC - i11;
                            if (i10 % 2 == 0) {
                                this.p.putShort((short) i12);
                            } else {
                                this.p.putInt(i12);
                            }
                            i10++;
                            i11 = iC;
                        }
                        int i13 = (i - this.U) - i11;
                        if ((i2 & 1) == 1) {
                            this.p.putInt(i13);
                        } else {
                            this.p.putShort((short) i13);
                            this.p.putInt(0);
                        }
                        byte[] bArrArray = this.p.array();
                        Kn kn4 = this.n;
                        kn4.h(i9, bArrArray);
                        interfaceC2380n0.b(kn4, i9, 1);
                        this.V += i9;
                    }
                }
            } else {
                byte[] bArr = c2252k1.j;
                if (bArr != null) {
                    kn.h(bArr.length, bArr);
                }
            }
            if (!"A_OPUS".equals(c2252k1.c) ? c2252k1.g > 0 : z) {
                this.Q |= 268435456;
                this.o.g(0);
                int i14 = (kn.c + i) - this.U;
                kn2.g(4);
                byte[] bArr2 = kn2.a;
                bArr2[0] = (byte) ((i14 >> 24) & 255);
                bArr2[1] = (byte) ((i14 >> 16) & 255);
                bArr2[2] = (byte) ((i14 >> 8) & 255);
                bArr2[3] = (byte) (i14 & 255);
                interfaceC2380n0.b(kn2, 4, 2);
                this.V += 4;
            }
            this.X = true;
        }
        int i15 = i + kn.c;
        if (!"V_MPEG4/ISO/AVC".equals(c2252k1.c) && !"V_MPEGH/ISO/HEVC".equals(c2252k1.c)) {
            if (c2252k1.V != null) {
                AbstractC1795We.L(kn.c == 0);
                c2252k1.V.c(p);
            }
            while (true) {
                int i16 = this.U;
                if (i16 >= i15) {
                    break;
                }
                int i17 = i15 - i16;
                int iS = kn.s();
                if (iS > 0) {
                    iD2 = Math.min(i17, iS);
                    interfaceC2380n0.e(iD2, kn);
                } else {
                    iD2 = interfaceC2380n0.d(p, i17, false);
                }
                this.U += iD2;
                this.V += iD2;
            }
        } else {
            Kn kn5 = this.g;
            byte[] bArr3 = kn5.a;
            bArr3[0] = 0;
            bArr3[1] = 0;
            bArr3[2] = 0;
            int i18 = c2252k1.a0;
            int i19 = 4 - i18;
            while (this.U < i15) {
                int i20 = this.W;
                if (i20 == 0) {
                    int iMin = Math.min(i18, kn.s());
                    p.h(bArr3, i19 + iMin, i18 - iMin, false);
                    if (iMin > 0) {
                        kn.f(i19, bArr3, iMin);
                    }
                    this.U += i18;
                    kn5.j(0);
                    this.W = kn5.C();
                    Kn kn6 = this.f;
                    kn6.j(0);
                    interfaceC2380n0.e(4, kn6);
                    this.V += 4;
                } else {
                    int iS2 = kn.s();
                    if (iS2 > 0) {
                        iD = Math.min(i20, iS2);
                        interfaceC2380n0.e(iD, kn);
                    } else {
                        iD = interfaceC2380n0.d(p, i20, false);
                    }
                    this.U += iD;
                    this.V += iD;
                    this.W -= iD;
                }
            }
        }
        if ("A_VORBIS".equals(c2252k1.c)) {
            Kn kn7 = this.i;
            kn7.j(0);
            interfaceC2380n0.e(4, kn7);
            this.V += 4;
        }
        int i21 = this.V;
        m();
        return i21;
    }

    public final long c(long j) throws zzaz {
        long j2 = this.s;
        if (j2 != -9223372036854775807L) {
            return Yo.v(j, j2, 1000L, RoundingMode.DOWN);
        }
        throw zzaz.a(null, "Can't scale timecode prior to timecodeScale being set.");
    }

    @Override // com.google.android.gms.internal.ads.U
    public final boolean d(V v) throws EOFException, InterruptedIOException {
        com.android.billingclient.api.s sVar = new com.android.billingclient.api.s(13, (byte) 0);
        P p = (P) v;
        long j = p.c;
        long j2 = 1024;
        if (j != -1 && j <= 1024) {
            j2 = j;
        }
        Kn kn = (Kn) sVar.c;
        P p2 = (P) v;
        p2.k(kn.a, 0, 4, false);
        long jH = kn.H();
        sVar.b = 4;
        while (true) {
            if (jH != 440786851) {
                int i = (int) j2;
                int i2 = sVar.b + 1;
                sVar.b = i2;
                if (i2 == i) {
                    break;
                }
                p2.k(kn.a, 0, 1, false);
                jH = ((jH << 8) & (-256)) | (kn.a[0] & 255);
            } else {
                long jR = sVar.r(p);
                long j3 = sVar.b;
                if (jR != Long.MIN_VALUE) {
                    long j4 = j3 + jR;
                    if (j == -1 || j4 < j) {
                        while (true) {
                            long j5 = sVar.b;
                            if (j5 < j4) {
                                if (sVar.r(p) != Long.MIN_VALUE) {
                                    long jR2 = sVar.r(p);
                                    if (jR2 < 0) {
                                        break;
                                    }
                                    if (jR2 != 0) {
                                        int i3 = (int) jR2;
                                        p2.n(i3, false);
                                        sVar.b += i3;
                                    }
                                } else {
                                    break;
                                }
                            } else if (j5 == j4) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void e(W w) {
        if (this.d) {
            w = new androidx.browser.customtabs.k(w, this.e);
        }
        this.d0 = w;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:46:0x00fa A[LOOP:1: B:6:0x0012->B:46:0x00fa, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:473:0x0108 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:474:0x01da A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:475:0x052b A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:476:0x0650 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:477:0x06ec A[SYNTHETIC] */
    @Override // com.google.android.gms.internal.ads.U
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int f(com.google.android.gms.internal.ads.V r37, androidx.compose.foundation.lazy.layout.C0429a r38) throws com.google.android.gms.internal.ads.zzaz, java.io.EOFException, java.io.InterruptedIOException {
        /*
            Method dump skipped, instructions count: 3100
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2295l1.f(com.google.android.gms.internal.ads.V, androidx.compose.foundation.lazy.layout.a):int");
    }

    public final void g(int i) throws zzaz {
        if (this.E == null || this.F == null) {
            throw zzaz.a(null, "Element " + i + " must be in a Cues");
        }
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void h(long j, long j2) {
        this.D = -9223372036854775807L;
        this.I = 0;
        C2209j1 c2209j1 = this.e0;
        c2209j1.e = 0;
        c2209j1.b.clear();
        C2338m1 c2338m1 = c2209j1.c;
        c2338m1.a = 0;
        c2338m1.b = 0;
        C2338m1 c2338m12 = this.a;
        c2338m12.a = 0;
        c2338m12.b = 0;
        m();
        int i = 0;
        while (true) {
            SparseArray sparseArray = this.b;
            if (i >= sparseArray.size()) {
                return;
            }
            C2423o0 c2423o0 = ((C2252k1) sparseArray.valueAt(i)).V;
            if (c2423o0 != null) {
                c2423o0.b = false;
                c2423o0.c = 0;
            }
            i++;
        }
    }

    public final void i(int i) throws zzaz {
        if (this.w != null) {
            return;
        }
        throw zzaz.a(null, "Element " + i + " must be in a TrackEntry");
    }

    @Override // com.google.android.gms.internal.ads.U
    public final List j() {
        C2244ju c2244ju = AbstractC2330lu.b;
        return Bu.e;
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x008e  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0093  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x00b1  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x00c3  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00e1  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x00d0 A[EDGE_INSN: B:62:0x00d0->B:51:0x00d0 BREAK  A[LOOP:0: B:45:0x00bf->B:50:0x00cd], SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void k(com.google.android.gms.internal.ads.C2252k1 r18, long r19, int r21, int r22, int r23) {
        /*
            Method dump skipped, instructions count: 262
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2295l1.k(com.google.android.gms.internal.ads.k1, long, int, int, int):void");
    }

    public final void l(P p, int i) throws EOFException, InterruptedIOException {
        Kn kn = this.h;
        if (kn.c >= i) {
            return;
        }
        byte[] bArr = kn.a;
        if (bArr.length < i) {
            int length = bArr.length;
            kn.e(Math.max(length + length, i));
        }
        byte[] bArr2 = kn.a;
        int i2 = kn.c;
        p.h(bArr2, i2, i - i2, false);
        kn.i(i);
    }

    public final void m() {
        this.U = 0;
        this.V = 0;
        this.W = 0;
        this.X = false;
        this.Y = false;
        this.Z = false;
        this.a0 = 0;
        this.b0 = (byte) 0;
        this.c0 = false;
        this.k.g(0);
    }

    public final void n(P p, byte[] bArr, int i) throws EOFException, InterruptedIOException {
        int length = bArr.length;
        int i2 = length + i;
        Kn kn = this.l;
        byte[] bArr2 = kn.a;
        if (bArr2.length < i2) {
            byte[] bArrCopyOf = Arrays.copyOf(bArr, i2 + i);
            kn.h(bArrCopyOf.length, bArrCopyOf);
        } else {
            System.arraycopy(bArr, 0, bArr2, 0, length);
        }
        p.h(kn.a, length, i, false);
        kn.j(0);
        kn.i(i2);
    }

    public C2295l1(C2209j1 c2209j1, int i, Z1 z1) {
        this.r = -1L;
        this.s = -9223372036854775807L;
        this.t = -9223372036854775807L;
        this.u = -9223372036854775807L;
        this.B = -1L;
        this.C = -1L;
        this.D = -9223372036854775807L;
        this.e0 = c2209j1;
        c2209j1.d = new Ts(this, 2);
        this.e = z1;
        this.c = true;
        this.d = (i & 2) == 0;
        this.a = new C2338m1(0);
        this.b = new SparseArray();
        this.h = new Kn(4);
        this.i = new Kn(ByteBuffer.allocate(4).putInt(-1).array());
        this.j = new Kn(4);
        this.f = new Kn(LA.w);
        this.g = new Kn(4);
        this.k = new Kn();
        this.l = new Kn();
        this.m = new Kn(8);
        this.n = new Kn();
        this.o = new Kn();
        this.N = new int[1];
    }
}
