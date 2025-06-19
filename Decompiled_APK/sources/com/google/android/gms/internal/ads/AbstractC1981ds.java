package com.google.android.gms.internal.ads;

import android.os.Build;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;

/* renamed from: com.google.android.gms.internal.ads.ds, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC1981ds {
    public static int a = 2;

    public static void A(int i, int i2, Object obj) {
        if (obj instanceof byte[]) {
            ((byte[]) obj)[i] = (byte) i2;
        } else if (obj instanceof short[]) {
            ((short[]) obj)[i] = (short) i2;
        } else {
            ((int[]) obj)[i] = i2;
        }
    }

    public static void C(boolean z) {
        if (!z) {
            throw new IllegalArgumentException();
        }
    }

    public static int D(long j) {
        if (j > 2147483647L) {
            return SubsamplingScaleImageView.TILE_SIZE_AUTO;
        }
        if (j < -2147483648L) {
            return Integer.MIN_VALUE;
        }
        return (int) j;
    }

    public static void E(String str, boolean z) {
        if (!z) {
            throw new IllegalArgumentException(str);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:4:0x000b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.Integer F(java.lang.String r15) {
        /*
            r0 = 1
            r15.getClass()
            boolean r1 = r15.isEmpty()
            r2 = 0
            if (r1 == 0) goto Le
        Lb:
            r15 = r2
            goto L7f
        Le:
            r1 = 0
            char r3 = r15.charAt(r1)
            r4 = 45
            if (r3 != r4) goto L18
            r1 = r0
        L18:
            int r5 = r15.length()
            if (r1 != r5) goto L1f
            goto Lb
        L1f:
            int r5 = r1 + 1
            char r1 = r15.charAt(r1)
            r6 = -1
            r7 = 128(0x80, float:1.8E-43)
            if (r1 >= r7) goto L2f
            byte[] r8 = com.google.android.gms.internal.ads.AbstractC1984dv.a
            r1 = r8[r1]
            goto L32
        L2f:
            byte[] r1 = com.google.android.gms.internal.ads.AbstractC1984dv.a
            r1 = r6
        L32:
            if (r1 < 0) goto Lb
            r8 = 10
            if (r1 < r8) goto L39
            goto Lb
        L39:
            int r1 = -r1
            long r9 = (long) r1
        L3b:
            int r1 = r15.length()
            r11 = -9223372036854775808
            if (r5 >= r1) goto L6e
            int r1 = r5 + 1
            char r5 = r15.charAt(r5)
            if (r5 >= r7) goto L50
            byte[] r13 = com.google.android.gms.internal.ads.AbstractC1984dv.a
            r5 = r13[r5]
            goto L53
        L50:
            byte[] r5 = com.google.android.gms.internal.ads.AbstractC1984dv.a
            r5 = r6
        L53:
            if (r5 < 0) goto Lb
            if (r5 >= r8) goto Lb
            r13 = -922337203685477580(0xf333333333333334, double:-8.390303882365713E246)
            int r13 = (r9 > r13 ? 1 : (r9 == r13 ? 0 : -1))
            if (r13 >= 0) goto L61
            goto Lb
        L61:
            r13 = 10
            long r9 = r9 * r13
            long r13 = (long) r5
            long r11 = r11 + r13
            int r5 = (r9 > r11 ? 1 : (r9 == r11 ? 0 : -1))
            if (r5 >= 0) goto L6b
            goto Lb
        L6b:
            long r9 = r9 - r13
            r5 = r1
            goto L3b
        L6e:
            if (r3 != r4) goto L75
            java.lang.Long r15 = java.lang.Long.valueOf(r9)
            goto L7f
        L75:
            int r15 = (r9 > r11 ? 1 : (r9 == r11 ? 0 : -1))
            if (r15 != 0) goto L7a
            goto Lb
        L7a:
            long r0 = -r9
            java.lang.Long r15 = java.lang.Long.valueOf(r0)
        L7f:
            if (r15 == 0) goto L98
            long r0 = r15.longValue()
            int r3 = r15.intValue()
            long r3 = (long) r3
            int r0 = (r0 > r3 ? 1 : (r0 == r3 ? 0 : -1))
            if (r0 == 0) goto L8f
            goto L98
        L8f:
            int r15 = r15.intValue()
            java.lang.Integer r15 = java.lang.Integer.valueOf(r15)
            return r15
        L98:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.AbstractC1981ds.F(java.lang.String):java.lang.Integer");
    }

    public static boolean G(byte b) {
        return b > -65;
    }

    public static List H(int... iArr) {
        int length = iArr.length;
        return length == 0 ? Collections.EMPTY_LIST : new C1941cv(0, length, iArr);
    }

    public static void I(String str, long j, boolean z) {
        if (!z) {
            throw new IllegalArgumentException(AbstractC2025es.r(str, Long.valueOf(j)));
        }
    }

    public static int[] J(AbstractC2459ou abstractC2459ou) {
        Object[] array = abstractC2459ou.toArray(AbstractC2071fu.a);
        int length = array.length;
        int[] iArr = new int[length];
        for (int i = 0; i < length; i++) {
            Object obj = array[i];
            obj.getClass();
            iArr[i] = ((Number) obj).intValue();
        }
        return iArr;
    }

    public static void K(int i, int i2, int i3) {
        if (i < 0 || i2 < i || i2 > i3) {
            throw new IndexOutOfBoundsException((i < 0 || i > i3) ? M(i, i3, "start index") : (i2 < 0 || i2 > i3) ? M(i2, i3, "end index") : AbstractC2025es.r("end index (%s) must not be less than start index (%s)", Integer.valueOf(i2), Integer.valueOf(i)));
        }
    }

    public static void L(String str, boolean z) {
        if (!z) {
            throw new IllegalStateException(str);
        }
    }

    public static String M(int i, int i2, String str) {
        if (i < 0) {
            return AbstractC2025es.r("%s (%s) must not be negative", str, Integer.valueOf(i));
        }
        if (i2 >= 0) {
            return AbstractC2025es.r("%s (%s) must not be greater than size (%s)", str, Integer.valueOf(i), Integer.valueOf(i2));
        }
        throw new IllegalArgumentException(android.support.v4.media.session.a.f(i2, "negative size: "));
    }

    public static long b(double d) {
        E("not a normal value", t(d));
        int exponent = Math.getExponent(d);
        long jDoubleToRawLongBits = Double.doubleToRawLongBits(d) & 4503599627370495L;
        return exponent == -1023 ? jDoubleToRawLongBits + jDoubleToRawLongBits : jDoubleToRawLongBits | 4503599627370496L;
    }

    public static C2326lq c(Lr lr) throws GeneralSecurityException, IOException {
        C2332lw c2332lw;
        ByteArrayInputStream byteArrayInputStream = (ByteArrayInputStream) lr.b;
        try {
            IA ia = IA.a;
            C2305lB c2305lB = C2305lB.c;
            Lz lzA = Lz.A(byteArrayInputStream, IA.b);
            byteArrayInputStream.close();
            if (lzA.w() <= 0) {
                throw new GeneralSecurityException("empty keyset");
            }
            ArrayList arrayList = new ArrayList(lzA.w());
            for (Kz kz : lzA.B()) {
                int iW = kz.w();
                try {
                    C2377my c2377myA = C2377my.a(kz.x().A(), kz.x().z(), kz.x().x(), kz.z(), kz.z() == Yz.RAW ? null : Integer.valueOf(kz.w()));
                    Xx xx = Xx.b;
                    C2634sy c2634sy = (C2634sy) xx.a.get();
                    c2634sy.getClass();
                    AbstractC2025es nx = !c2634sy.b.containsKey(new C2549qy(C2377my.class, c2377myA.b)) ? new Nx(c2377myA) : xx.a(c2377myA);
                    int iE = kz.E() - 2;
                    boolean z = true;
                    if (iE == 1) {
                        c2332lw = C2332lw.c;
                    } else if (iE == 2) {
                        c2332lw = C2332lw.d;
                    } else {
                        if (iE != 3) {
                            throw new GeneralSecurityException("Unknown key status");
                        }
                        c2332lw = C2332lw.e;
                    }
                    if (iW != lzA.x()) {
                        z = false;
                    }
                    arrayList.add(new C2418nw(nx, c2332lw, iW, z));
                } catch (GeneralSecurityException e) {
                    if (Cx.a.a.get()) {
                        throw new GeneralSecurityException("Parsing of a single key failed (maybe wrong status?) and Tink is configured via validateKeysetsOnParsing to reject such keysets.", e);
                    }
                    arrayList.add(null);
                }
            }
            return new C2326lq(lzA, Collections.unmodifiableList(arrayList), Px.b);
        } catch (Throwable th) {
            byteArrayInputStream.close();
            throw th;
        }
    }

    public static void d(byte b, byte b2, byte b3, byte b4, char[] cArr, int i) throws zzgzh {
        if (!G(b2)) {
            if ((((b2 + 112) + (b << 28)) >> 30) == 0 && !G(b3) && !G(b4)) {
                int i2 = ((b & 7) << 18) | ((b2 & 63) << 12) | ((b3 & 63) << 6) | (b4 & 63);
                cArr[i] = (char) ((i2 >>> 10) + 55232);
                cArr[i + 1] = (char) ((i2 & 1023) + 56320);
                return;
            }
        }
        throw new zzgzh("Protocol message had invalid UTF-8.");
    }

    public static void e(int i) throws InvalidAlgorithmParameterException {
        if (i != 16 && i != 32) {
            throw new InvalidAlgorithmParameterException(String.format("invalid key size %d; only 128-bit and 256-bit AES keys are supported", Integer.valueOf(i * 8)));
        }
    }

    public static void f(int i, int i2) {
        String strR;
        if (i < 0 || i >= i2) {
            if (i < 0) {
                strR = AbstractC2025es.r("%s (%s) must not be negative", "index", Integer.valueOf(i));
            } else {
                if (i2 < 0) {
                    throw new IllegalArgumentException(android.support.v4.media.session.a.f(i2, "negative size: "));
                }
                strR = AbstractC2025es.r("%s (%s) must be less than size (%s)", "index", Integer.valueOf(i), Integer.valueOf(i2));
            }
            throw new IndexOutOfBoundsException(strR);
        }
    }

    public static void g(Object obj, String str) {
        if (obj == null) {
            throw new NullPointerException(str);
        }
    }

    public static /* synthetic */ void h(AtomicReference atomicReference, RuntimeException runtimeException) {
        while (!atomicReference.compareAndSet(null, runtimeException)) {
            if (atomicReference.get() != null && atomicReference.get() != null) {
                return;
            }
        }
    }

    public static boolean j(int i) {
        Boolean bool;
        if (i - 1 == 0) {
            return !Dx.a();
        }
        if (!Dx.a()) {
            return true;
        }
        try {
            bool = (Boolean) Class.forName("org.conscrypt.Conscrypt").getMethod("isBoringSslFIPSBuild", null).invoke(null, null);
        } catch (Exception unused) {
            Dx.a.logp(Level.INFO, "com.google.crypto.tink.config.internal.TinkFipsUtil", "checkConscryptIsAvailableAndUsesFipsBoringSsl", "Conscrypt is not available or does not support checking for FIPS build.");
            bool = Boolean.FALSE;
        }
        return bool.booleanValue();
    }

    public static int k(long j) {
        int i = (int) j;
        I("Out of range: %s", j, ((long) i) == j);
        return i;
    }

    /* JADX WARN: Removed duplicated region for block: B:111:0x018f  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00d1  */
    /* JADX WARN: Removed duplicated region for block: B:97:0x016f  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x0172  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final int l(android.content.Context r16, androidx.browser.customtabs.k r17) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 412
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.AbstractC1981ds.l(android.content.Context, androidx.browser.customtabs.k):int");
    }

    public static int m(Object obj, Object obj2, int i, Object obj3, int[] iArr, Object[] objArr, Object[] objArr2) {
        int i2;
        int i3;
        int iM = AbstractC2457os.m(obj);
        int i4 = iM & i;
        int iU = u(i4, obj3);
        if (iU != 0) {
            int i5 = ~i;
            int i6 = iM & i5;
            int i7 = -1;
            while (true) {
                i2 = iU - 1;
                int i8 = iArr[i2];
                i3 = i8 & i;
                if ((i8 & i5) != i6 || !AbstractC2457os.l(obj, objArr[i2]) || (objArr2 != null && !AbstractC2457os.l(obj2, objArr2[i2]))) {
                    if (i3 == 0) {
                        break;
                    }
                    i7 = i2;
                    iU = i3;
                } else {
                    break;
                }
            }
            if (i7 == -1) {
                A(i4, i3, obj3);
                return i2;
            }
            iArr[i7] = (iArr[i7] & i5) | (i3 & i);
            return i2;
        }
        return -1;
    }

    public static AbstractList n(List list, InterfaceC2544qt interfaceC2544qt) {
        return list != null ? new C2673tu(list, interfaceC2544qt) : new C2716uu(list, interfaceC2544qt);
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0013  */
    /* JADX WARN: Removed duplicated region for block: B:12:0x0016 A[PHI: r2
  0x0016: PHI (r2v3 byte) = (r2v2 byte), (r2v9 byte) binds: [B:9:0x0011, B:11:0x0015] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:14:0x001c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void o(byte r2, byte r3, byte r4, char[] r5, int r6) throws com.google.android.gms.internal.ads.zzgzh {
        /*
            boolean r0 = G(r3)
            if (r0 != 0) goto L2c
            r0 = -96
            r1 = -32
            if (r2 != r1) goto Lf
            if (r3 < r0) goto L2c
            r2 = r1
        Lf:
            r1 = -19
            if (r2 != r1) goto L16
            if (r3 >= r0) goto L2c
            r2 = r1
        L16:
            boolean r0 = G(r4)
            if (r0 != 0) goto L2c
            r2 = r2 & 15
            r3 = r3 & 63
            r4 = r4 & 63
            int r2 = r2 << 12
            int r3 = r3 << 6
            r2 = r2 | r3
            r2 = r2 | r4
            char r2 = (char) r2
            r5[r6] = r2
            return
        L2c:
            com.google.android.gms.internal.ads.zzgzh r2 = new com.google.android.gms.internal.ads.zzgzh
            java.lang.String r3 = "Protocol message had invalid UTF-8."
            r2.<init>(r3)
            throw r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.AbstractC1981ds.o(byte, byte, byte, char[], int):void");
    }

    public static void p(int i, int i2) {
        if (i < 0 || i > i2) {
            throw new IndexOutOfBoundsException(M(i, i2, "index"));
        }
    }

    public static void s(Object obj) {
        if (obj == null) {
            throw new NullPointerException("Cannot return null from a non-@Nullable @Provides method");
        }
    }

    public static boolean t(double d) {
        return Math.getExponent(d) <= 1023;
    }

    public static int u(int i, Object obj) {
        return obj instanceof byte[] ? ((byte[]) obj)[i] & 255 : obj instanceof short[] ? (char) ((short[]) obj)[i] : ((int[]) obj)[i];
    }

    public static void v(byte b, byte b2, char[] cArr, int i) throws zzgzh {
        if (b < -62 || G(b2)) {
            throw new zzgzh("Protocol message had invalid UTF-8.");
        }
        cArr[i] = (char) (((b & 31) << 6) | (b2 & 63));
    }

    public static void w(Class cls, Object obj) {
        if (obj == null) {
            throw new IllegalStateException(String.valueOf(cls.getCanonicalName()).concat(" must be set"));
        }
    }

    public static void x(Object obj, String str) {
        if (obj == null) {
            throw new NullPointerException(str);
        }
    }

    public static Object y(int i) {
        if (i < 2 || i > 1073741824 || Integer.highestOneBit(i) != i) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "must be power of 2 between 2^1 and 2^30: "));
        }
        return i <= 256 ? new byte[i] : i <= 65536 ? new short[i] : new int[i];
    }

    public static final void z(byte[] bArr, String str, androidx.browser.customtabs.k kVar) {
        StringBuilder sb = new StringBuilder("os.arch:");
        sb.append(System.getProperty("os.arch"));
        sb.append(";");
        try {
            String[] strArr = (String[]) Build.class.getField("SUPPORTED_ABIS").get(null);
            if (strArr != null) {
                sb.append("supported_abis:");
                sb.append(Arrays.toString(strArr));
                sb.append(";");
            }
        } catch (IllegalAccessException | NoSuchFieldException unused) {
        }
        sb.append("CPU_ABI:");
        sb.append(Build.CPU_ABI);
        sb.append(";CPU_ABI2:");
        sb.append(Build.CPU_ABI2);
        sb.append(";");
        if (bArr != null) {
            sb.append("ELF:");
            sb.append(Arrays.toString(bArr));
            sb.append(";");
        }
        if (str != null) {
            sb.append("dbg:");
            sb.append(str);
            sb.append(";");
        }
        kVar.u(4007, 0L, null, null, sb.toString());
    }

    public abstract int a(Av av);

    public abstract void q(Av av, Set set);
}
