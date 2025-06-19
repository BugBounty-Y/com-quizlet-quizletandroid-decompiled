package com.google.android.gms.internal.play_billing;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.appsflyer.attribution.RequestError;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.ads.C2776wA;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;
import sun.misc.Unsafe;

/* renamed from: com.google.android.gms.internal.play_billing.r1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3831r1 implements InterfaceC3852y1 {
    public static final int[] j = new int[0];
    public static final Unsafe k = G1.h();
    public final int[] a;
    public final Object[] b;
    public final int c;
    public final int d;
    public final P0 e;
    public final int[] f;
    public final int g;
    public final int h;
    public final C3781a1 i;

    public C3831r1(int[] iArr, Object[] objArr, int i, int i2, P0 p0, int[] iArr2, int i3, int i4, C3781a1 c3781a1, C3781a1 c3781a12) {
        this.a = iArr;
        this.b = objArr;
        this.c = i;
        this.d = i2;
        this.f = iArr2;
        this.g = i3;
        this.h = i4;
        this.i = c3781a1;
        this.e = p0;
    }

    public static Field D(Class cls, String str) {
        try {
            return cls.getDeclaredField(str);
        } catch (NoSuchFieldException unused) {
            Field[] declaredFields = cls.getDeclaredFields();
            for (Field field : declaredFields) {
                if (str.equals(field.getName())) {
                    return field;
                }
            }
            String name = cls.getName();
            String string = Arrays.toString(declaredFields);
            StringBuilder sbH = AbstractC0147y.h("Field ", str, " for ", name, " not found. Known fields are ");
            sbH.append(string);
            throw new RuntimeException(sbH.toString());
        }
    }

    public static boolean q(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj instanceof AbstractC3787c1) {
            return ((AbstractC3787c1) obj).c();
        }
        return true;
    }

    /* JADX WARN: Removed duplicated region for block: B:126:0x0271  */
    /* JADX WARN: Removed duplicated region for block: B:128:0x0277  */
    /* JADX WARN: Removed duplicated region for block: B:131:0x028f  */
    /* JADX WARN: Removed duplicated region for block: B:132:0x0292  */
    /* JADX WARN: Removed duplicated region for block: B:170:0x0356  */
    /* JADX WARN: Removed duplicated region for block: B:185:0x03a8  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.google.android.gms.internal.play_billing.C3831r1 t(com.google.android.gms.internal.play_billing.C3849x1 r34, com.google.android.gms.internal.play_billing.C3781a1 r35, com.google.android.gms.internal.play_billing.C3781a1 r36) {
        /*
            Method dump skipped, instructions count: 1048
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.play_billing.C3831r1.t(com.google.android.gms.internal.play_billing.x1, com.google.android.gms.internal.play_billing.a1, com.google.android.gms.internal.play_billing.a1):com.google.android.gms.internal.play_billing.r1");
    }

    public static int u(long j2, Object obj) {
        return ((Integer) G1.g(j2, obj)).intValue();
    }

    public static int w(int i) {
        return (i >>> 20) & 255;
    }

    public static long y(long j2, Object obj) {
        return ((Long) G1.g(j2, obj)).longValue();
    }

    public final InterfaceC3852y1 A(int i) {
        int i2 = i / 3;
        int i3 = i2 + i2;
        Object[] objArr = this.b;
        InterfaceC3852y1 interfaceC3852y1 = (InterfaceC3852y1) objArr[i3];
        if (interfaceC3852y1 != null) {
            return interfaceC3852y1;
        }
        InterfaceC3852y1 interfaceC3852y1A = C3843v1.c.a((Class) objArr[i3 + 1]);
        objArr[i3] = interfaceC3852y1A;
        return interfaceC3852y1A;
    }

    public final Object B(int i, Object obj) {
        InterfaceC3852y1 interfaceC3852y1A = A(i);
        int iX = x(i) & 1048575;
        if (!o(i, obj)) {
            return interfaceC3852y1A.zze();
        }
        Object object = k.getObject(obj, iX);
        if (q(object)) {
            return object;
        }
        AbstractC3787c1 abstractC3787c1Zze = interfaceC3852y1A.zze();
        if (object != null) {
            interfaceC3852y1A.b(abstractC3787c1Zze, object);
        }
        return abstractC3787c1Zze;
    }

    public final Object C(int i, int i2, Object obj) {
        InterfaceC3852y1 interfaceC3852y1A = A(i2);
        if (!r(i, i2, obj)) {
            return interfaceC3852y1A.zze();
        }
        Object object = k.getObject(obj, x(i2) & 1048575);
        if (q(object)) {
            return object;
        }
        AbstractC3787c1 abstractC3787c1Zze = interfaceC3852y1A.zze();
        if (object != null) {
            interfaceC3852y1A.b(abstractC3787c1Zze, object);
        }
        return abstractC3787c1Zze;
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x0071  */
    @Override // com.google.android.gms.internal.play_billing.InterfaceC3852y1
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(java.lang.Object r8) {
        /*
            r7 = this;
            boolean r0 = q(r8)
            if (r0 != 0) goto L8
            goto L96
        L8:
            boolean r0 = r8 instanceof com.google.android.gms.internal.play_billing.AbstractC3787c1
            r1 = 0
            if (r0 == 0) goto L18
            r0 = r8
            com.google.android.gms.internal.play_billing.c1 r0 = (com.google.android.gms.internal.play_billing.AbstractC3787c1) r0
            r0.l()
            r0.zza = r1
            r0.j()
        L18:
            r0 = r1
        L19:
            int[] r2 = r7.a
            int r3 = r2.length
            if (r0 >= r3) goto L87
            int r3 = r7.x(r0)
            r4 = 1048575(0xfffff, float:1.469367E-39)
            r4 = r4 & r3
            int r3 = w(r3)
            long r4 = (long) r4
            r6 = 9
            if (r3 == r6) goto L71
            r6 = 60
            if (r3 == r6) goto L5b
            r6 = 68
            if (r3 == r6) goto L5b
            switch(r3) {
                case 17: goto L71;
                case 18: goto L4c;
                case 19: goto L4c;
                case 20: goto L4c;
                case 21: goto L4c;
                case 22: goto L4c;
                case 23: goto L4c;
                case 24: goto L4c;
                case 25: goto L4c;
                case 26: goto L4c;
                case 27: goto L4c;
                case 28: goto L4c;
                case 29: goto L4c;
                case 30: goto L4c;
                case 31: goto L4c;
                case 32: goto L4c;
                case 33: goto L4c;
                case 34: goto L4c;
                case 35: goto L4c;
                case 36: goto L4c;
                case 37: goto L4c;
                case 38: goto L4c;
                case 39: goto L4c;
                case 40: goto L4c;
                case 41: goto L4c;
                case 42: goto L4c;
                case 43: goto L4c;
                case 44: goto L4c;
                case 45: goto L4c;
                case 46: goto L4c;
                case 47: goto L4c;
                case 48: goto L4c;
                case 49: goto L4c;
                case 50: goto L3b;
                default: goto L3a;
            }
        L3a:
            goto L84
        L3b:
            sun.misc.Unsafe r2 = com.google.android.gms.internal.play_billing.C3831r1.k
            java.lang.Object r3 = r2.getObject(r8, r4)
            if (r3 == 0) goto L84
            r6 = r3
            com.google.android.gms.internal.play_billing.n1 r6 = (com.google.android.gms.internal.play_billing.C3820n1) r6
            r6.a = r1
            r2.putObject(r8, r4, r3)
            goto L84
        L4c:
            java.lang.Object r2 = com.google.android.gms.internal.play_billing.G1.g(r4, r8)
            com.google.android.gms.internal.play_billing.g1 r2 = (com.google.android.gms.internal.play_billing.InterfaceC3799g1) r2
            com.google.android.gms.internal.play_billing.Q0 r2 = (com.google.android.gms.internal.play_billing.Q0) r2
            boolean r3 = r2.a
            if (r3 == 0) goto L84
            r2.a = r1
            goto L84
        L5b:
            r2 = r2[r0]
            boolean r2 = r7.r(r2, r0, r8)
            if (r2 == 0) goto L84
            com.google.android.gms.internal.play_billing.y1 r2 = r7.A(r0)
            sun.misc.Unsafe r3 = com.google.android.gms.internal.play_billing.C3831r1.k
            java.lang.Object r3 = r3.getObject(r8, r4)
            r2.a(r3)
            goto L84
        L71:
            boolean r2 = r7.o(r0, r8)
            if (r2 == 0) goto L84
            com.google.android.gms.internal.play_billing.y1 r2 = r7.A(r0)
            sun.misc.Unsafe r3 = com.google.android.gms.internal.play_billing.C3831r1.k
            java.lang.Object r3 = r3.getObject(r8, r4)
            r2.a(r3)
        L84:
            int r0 = r0 + 3
            goto L19
        L87:
            com.google.android.gms.internal.play_billing.a1 r0 = r7.i
            r0.getClass()
            com.google.android.gms.internal.play_billing.c1 r8 = (com.google.android.gms.internal.play_billing.AbstractC3787c1) r8
            com.google.android.gms.internal.play_billing.B1 r8 = r8.zzc
            boolean r0 = r8.e
            if (r0 == 0) goto L96
            r8.e = r1
        L96:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.play_billing.C3831r1.a(java.lang.Object):void");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:9:0x0022  */
    @Override // com.google.android.gms.internal.play_billing.InterfaceC3852y1
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(java.lang.Object r13, java.lang.Object r14) {
        /*
            Method dump skipped, instructions count: 628
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.play_billing.C3831r1.b(java.lang.Object, java.lang.Object):void");
    }

    @Override // com.google.android.gms.internal.play_billing.InterfaceC3852y1
    public final boolean c(Object obj) {
        int i;
        int i2;
        int i3;
        int i4 = 0;
        int i5 = 0;
        int i6 = 1048575;
        while (i5 < this.g) {
            int i7 = this.f[i5];
            int[] iArr = this.a;
            int i8 = iArr[i7];
            int iX = x(i7);
            int i9 = iArr[i7 + 2];
            int i10 = i9 & 1048575;
            int i11 = 1 << (i9 >>> 20);
            if (i10 != i6) {
                if (i10 != 1048575) {
                    i4 = k.getInt(obj, i10);
                }
                i2 = i7;
                i3 = i4;
                i = i10;
            } else {
                int i12 = i4;
                i = i6;
                i2 = i7;
                i3 = i12;
            }
            if ((268435456 & iX) == 0 || p(obj, i2, i, i3, i11)) {
                int iW = w(iX);
                if (iW != 9 && iW != 17) {
                    if (iW != 27) {
                        if (iW == 60 || iW == 68) {
                            if (!r(i8, i2, obj) || A(i2).c(G1.g(iX & 1048575, obj))) {
                            }
                        } else if (iW != 49) {
                            if (iW == 50 && !((C3820n1) G1.g(iX & 1048575, obj)).isEmpty()) {
                                int i13 = i2 / 3;
                                throw androidx.compose.animation.d0.l(this.b[i13 + i13]);
                            }
                        }
                        i5++;
                        i6 = i;
                        i4 = i3;
                    }
                    List list = (List) G1.g(iX & 1048575, obj);
                    if (list.isEmpty()) {
                        continue;
                    } else {
                        InterfaceC3852y1 interfaceC3852y1A = A(i2);
                        for (int i14 = 0; i14 < list.size(); i14++) {
                            if (interfaceC3852y1A.c(list.get(i14))) {
                            }
                        }
                    }
                    i5++;
                    i6 = i;
                    i4 = i3;
                } else if (!p(obj, i2, i, i3, i11) || A(i2).c(G1.g(iX & 1048575, obj))) {
                    i5++;
                    i6 = i;
                    i4 = i3;
                }
            }
            return false;
        }
        return true;
    }

    /* JADX WARN: Removed duplicated region for block: B:142:0x03c0  */
    /* JADX WARN: Removed duplicated region for block: B:186:0x04db  */
    @Override // com.google.android.gms.internal.play_billing.InterfaceC3852y1
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int d(com.google.android.gms.internal.play_billing.AbstractC3787c1 r18) {
        /*
            Method dump skipped, instructions count: 1950
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.play_billing.C3831r1.d(com.google.android.gms.internal.play_billing.c1):int");
    }

    @Override // com.google.android.gms.internal.play_billing.InterfaceC3852y1
    public final void e(Object obj, byte[] bArr, int i, int i2, C2776wA c2776wA) {
        s(obj, bArr, i, i2, 0, c2776wA);
    }

    /* JADX WARN: Removed duplicated region for block: B:44:0x00db A[PHI: r1
  0x00db: PHI (r1v34 int) = (r1v10 int), (r1v35 int) binds: [B:85:0x01ea, B:43:0x00d9] A[DONT_GENERATE, DONT_INLINE]] */
    @Override // com.google.android.gms.internal.play_billing.InterfaceC3852y1
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int f(com.google.android.gms.internal.play_billing.AbstractC3787c1 r11) {
        /*
            Method dump skipped, instructions count: 726
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.play_billing.C3831r1.f(com.google.android.gms.internal.play_billing.c1):int");
    }

    @Override // com.google.android.gms.internal.play_billing.InterfaceC3852y1
    public final boolean g(AbstractC3787c1 abstractC3787c1, AbstractC3787c1 abstractC3787c12) {
        boolean zE;
        int i = 0;
        while (true) {
            int[] iArr = this.a;
            if (i < iArr.length) {
                int iX = x(i);
                long j2 = iX & 1048575;
                switch (w(iX)) {
                    case 0:
                        if (!n(abstractC3787c1, abstractC3787c12, i)) {
                            break;
                        } else {
                            F1 f1 = G1.c;
                            if (Double.doubleToLongBits(f1.a(j2, abstractC3787c1)) != Double.doubleToLongBits(f1.a(j2, abstractC3787c12))) {
                                break;
                            } else {
                                continue;
                                i += 3;
                            }
                        }
                    case 1:
                        if (!n(abstractC3787c1, abstractC3787c12, i)) {
                            break;
                        } else {
                            F1 f12 = G1.c;
                            if (Float.floatToIntBits(f12.b(j2, abstractC3787c1)) != Float.floatToIntBits(f12.b(j2, abstractC3787c12))) {
                                break;
                            } else {
                                continue;
                                i += 3;
                            }
                        }
                    case 2:
                        if (!n(abstractC3787c1, abstractC3787c12, i) || G1.e(j2, abstractC3787c1) != G1.e(j2, abstractC3787c12)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 3:
                        if (!n(abstractC3787c1, abstractC3787c12, i) || G1.e(j2, abstractC3787c1) != G1.e(j2, abstractC3787c12)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 4:
                        if (!n(abstractC3787c1, abstractC3787c12, i) || G1.d(j2, abstractC3787c1) != G1.d(j2, abstractC3787c12)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 5:
                        if (!n(abstractC3787c1, abstractC3787c12, i) || G1.e(j2, abstractC3787c1) != G1.e(j2, abstractC3787c12)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 6:
                        if (!n(abstractC3787c1, abstractC3787c12, i) || G1.d(j2, abstractC3787c1) != G1.d(j2, abstractC3787c12)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 7:
                        if (!n(abstractC3787c1, abstractC3787c12, i)) {
                            break;
                        } else {
                            F1 f13 = G1.c;
                            if (f13.g(j2, abstractC3787c1) != f13.g(j2, abstractC3787c12)) {
                                break;
                            } else {
                                continue;
                                i += 3;
                            }
                        }
                    case 8:
                        if (!n(abstractC3787c1, abstractC3787c12, i) || !AbstractC3855z1.e(G1.g(j2, abstractC3787c1), G1.g(j2, abstractC3787c12))) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 9:
                        if (!n(abstractC3787c1, abstractC3787c12, i) || !AbstractC3855z1.e(G1.g(j2, abstractC3787c1), G1.g(j2, abstractC3787c12))) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 10:
                        if (!n(abstractC3787c1, abstractC3787c12, i) || !AbstractC3855z1.e(G1.g(j2, abstractC3787c1), G1.g(j2, abstractC3787c12))) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 11:
                        if (!n(abstractC3787c1, abstractC3787c12, i) || G1.d(j2, abstractC3787c1) != G1.d(j2, abstractC3787c12)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 12:
                        if (!n(abstractC3787c1, abstractC3787c12, i) || G1.d(j2, abstractC3787c1) != G1.d(j2, abstractC3787c12)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 13:
                        if (!n(abstractC3787c1, abstractC3787c12, i) || G1.d(j2, abstractC3787c1) != G1.d(j2, abstractC3787c12)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 14:
                        if (!n(abstractC3787c1, abstractC3787c12, i) || G1.e(j2, abstractC3787c1) != G1.e(j2, abstractC3787c12)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 15:
                        if (!n(abstractC3787c1, abstractC3787c12, i) || G1.d(j2, abstractC3787c1) != G1.d(j2, abstractC3787c12)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 16:
                        if (!n(abstractC3787c1, abstractC3787c12, i) || G1.e(j2, abstractC3787c1) != G1.e(j2, abstractC3787c12)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 17:
                        if (!n(abstractC3787c1, abstractC3787c12, i) || !AbstractC3855z1.e(G1.g(j2, abstractC3787c1), G1.g(j2, abstractC3787c12))) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 18:
                    case 19:
                    case 20:
                    case 21:
                    case EventType.WINDOW_STATE /* 22 */:
                    case EventType.AUDIO /* 23 */:
                    case EventType.VIDEO /* 24 */:
                    case EventType.SUBS /* 25 */:
                    case EventType.CDN /* 26 */:
                    case 27:
                    case 28:
                    case 29:
                    case 30:
                    case 31:
                    case 32:
                    case 33:
                    case 34:
                    case 35:
                    case 36:
                    case 37:
                    case 38:
                    case 39:
                    case RequestError.NETWORK_FAILURE /* 40 */:
                    case RequestError.NO_DEV_KEY /* 41 */:
                    case 42:
                    case 43:
                    case 44:
                    case 45:
                    case 46:
                    case 47:
                    case 48:
                    case 49:
                        zE = AbstractC3855z1.e(G1.g(j2, abstractC3787c1), G1.g(j2, abstractC3787c12));
                        break;
                    case RequestError.RESPONSE_CODE_FAILURE /* 50 */:
                        zE = AbstractC3855z1.e(G1.g(j2, abstractC3787c1), G1.g(j2, abstractC3787c12));
                        break;
                    case 51:
                    case 52:
                    case 53:
                    case 54:
                    case 55:
                    case 56:
                    case 57:
                    case 58:
                    case 59:
                    case 60:
                    case 61:
                    case 62:
                    case 63:
                    case 64:
                    case 65:
                    case 66:
                    case 67:
                    case 68:
                        long j3 = iArr[i + 2] & 1048575;
                        if (G1.d(j3, abstractC3787c1) != G1.d(j3, abstractC3787c12) || !AbstractC3855z1.e(G1.g(j2, abstractC3787c1), G1.g(j2, abstractC3787c12))) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    default:
                        i += 3;
                }
                if (zE) {
                    i += 3;
                }
            } else if (abstractC3787c1.zzc.equals(abstractC3787c12.zzc)) {
                return true;
            }
        }
        return false;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    @Override // com.google.android.gms.internal.play_billing.InterfaceC3852y1
    public final void h(Object obj, C3817m1 c3817m1) throws zzgp {
        int i;
        int i2;
        boolean z;
        C3831r1 c3831r1 = this;
        Unsafe unsafe = k;
        int i3 = 1048575;
        int i4 = 1048575;
        int i5 = 0;
        int i6 = 0;
        while (true) {
            int[] iArr = c3831r1.a;
            if (i5 >= iArr.length) {
                ((AbstractC3787c1) obj).zzc.d(c3817m1);
                return;
            }
            int iX = c3831r1.x(i5);
            int iW = w(iX);
            int i7 = iArr[i5];
            if (iW <= 17) {
                int i8 = iArr[i5 + 2];
                int i9 = i8 & i3;
                if (i9 != i4) {
                    i6 = i9 == i3 ? 0 : unsafe.getInt(obj, i9);
                    i4 = i9;
                }
                i = 1 << (i8 >>> 20);
            } else {
                i = 0;
            }
            long j2 = iX & i3;
            switch (iW) {
                case 0:
                    if (c3831r1.p(obj, i5, i4, i6, i)) {
                        ((V0) c3817m1.a).T(i7, Double.doubleToRawLongBits(G1.c.a(j2, obj)));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 1:
                    if (c3831r1.p(obj, i5, i4, i6, i)) {
                        ((V0) c3817m1.a).R(i7, Float.floatToRawIntBits(G1.c.b(j2, obj)));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 2:
                    if (c3831r1.p(obj, i5, i4, i6, i)) {
                        ((V0) c3817m1.a).b0(i7, unsafe.getLong(obj, j2));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 3:
                    if (c3831r1.p(obj, i5, i4, i6, i)) {
                        ((V0) c3817m1.a).b0(i7, unsafe.getLong(obj, j2));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 4:
                    if (c3831r1.p(obj, i5, i4, i6, i)) {
                        ((V0) c3817m1.a).V(i7, unsafe.getInt(obj, j2));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 5:
                    if (c3831r1.p(obj, i5, i4, i6, i)) {
                        ((V0) c3817m1.a).T(i7, unsafe.getLong(obj, j2));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 6:
                    if (c3831r1.p(obj, i5, i4, i6, i)) {
                        ((V0) c3817m1.a).R(i7, unsafe.getInt(obj, j2));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 7:
                    if (c3831r1.p(obj, i5, i4, i6, i)) {
                        byte bG = G1.c.g(j2, obj);
                        V0 v0 = (V0) c3817m1.a;
                        v0.a0(i7 << 3);
                        int i10 = v0.e;
                        try {
                            i2 = i10 + 1;
                        } catch (IndexOutOfBoundsException e) {
                            e = e;
                        }
                        try {
                            v0.c[i10] = bG;
                            v0.e = i2;
                        } catch (IndexOutOfBoundsException e2) {
                            e = e2;
                            i10 = i2;
                            throw new zzgp(i10, v0.d, 1, e);
                        }
                    } else {
                        continue;
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 8:
                    if (c3831r1.p(obj, i5, i4, i6, i)) {
                        Object object = unsafe.getObject(obj, j2);
                        if (object instanceof String) {
                            ((V0) c3817m1.a).X(i7, (String) object);
                        } else {
                            ((V0) c3817m1.a).Q(i7, (U0) object);
                        }
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 9:
                    if (c3831r1.p(obj, i5, i4, i6, i)) {
                        c3817m1.b(i7, unsafe.getObject(obj, j2), c3831r1.A(i5));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 10:
                    if (c3831r1.p(obj, i5, i4, i6, i)) {
                        ((V0) c3817m1.a).Q(i7, (U0) unsafe.getObject(obj, j2));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 11:
                    if (c3831r1.p(obj, i5, i4, i6, i)) {
                        ((V0) c3817m1.a).Z(i7, unsafe.getInt(obj, j2));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 12:
                    if (c3831r1.p(obj, i5, i4, i6, i)) {
                        ((V0) c3817m1.a).V(i7, unsafe.getInt(obj, j2));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 13:
                    if (c3831r1.p(obj, i5, i4, i6, i)) {
                        ((V0) c3817m1.a).R(i7, unsafe.getInt(obj, j2));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 14:
                    if (c3831r1.p(obj, i5, i4, i6, i)) {
                        ((V0) c3817m1.a).T(i7, unsafe.getLong(obj, j2));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 15:
                    if (c3831r1.p(obj, i5, i4, i6, i)) {
                        int i11 = unsafe.getInt(obj, j2);
                        ((V0) c3817m1.a).Z(i7, (i11 >> 31) ^ (i11 + i11));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 16:
                    if (c3831r1.p(obj, i5, i4, i6, i)) {
                        long j3 = unsafe.getLong(obj, j2);
                        ((V0) c3817m1.a).b0(i7, (j3 + j3) ^ (j3 >> 63));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 17:
                    if (c3831r1.p(obj, i5, i4, i6, i)) {
                        c3817m1.a(i7, unsafe.getObject(obj, j2), c3831r1.A(i5));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 18:
                    AbstractC3855z1.r(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 19:
                    AbstractC3855z1.v(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 20:
                    AbstractC3855z1.x(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 21:
                    AbstractC3855z1.d(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case EventType.WINDOW_STATE /* 22 */:
                    AbstractC3855z1.w(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case EventType.AUDIO /* 23 */:
                    AbstractC3855z1.u(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case EventType.VIDEO /* 24 */:
                    AbstractC3855z1.t(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case EventType.SUBS /* 25 */:
                    AbstractC3855z1.q(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case EventType.CDN /* 26 */:
                    int i12 = iArr[i5];
                    List list = (List) unsafe.getObject(obj, j2);
                    C3781a1 c3781a1 = AbstractC3855z1.a;
                    if (list != null && !list.isEmpty()) {
                        c3817m1.getClass();
                        for (int i13 = 0; i13 < list.size(); i13++) {
                            ((V0) c3817m1.a).X(i12, (String) list.get(i13));
                        }
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                    break;
                case 27:
                    int i14 = iArr[i5];
                    List list2 = (List) unsafe.getObject(obj, j2);
                    InterfaceC3852y1 interfaceC3852y1A = c3831r1.A(i5);
                    C3781a1 c3781a12 = AbstractC3855z1.a;
                    if (list2 != null && !list2.isEmpty()) {
                        for (int i15 = 0; i15 < list2.size(); i15++) {
                            c3817m1.b(i14, list2.get(i15), interfaceC3852y1A);
                        }
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                    break;
                case 28:
                    int i16 = iArr[i5];
                    List list3 = (List) unsafe.getObject(obj, j2);
                    C3781a1 c3781a13 = AbstractC3855z1.a;
                    if (list3 != null && !list3.isEmpty()) {
                        c3817m1.getClass();
                        for (int i17 = 0; i17 < list3.size(); i17++) {
                            ((V0) c3817m1.a).Q(i16, (U0) list3.get(i17));
                        }
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                    break;
                case 29:
                    z = false;
                    AbstractC3855z1.c(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 30:
                    z = false;
                    AbstractC3855z1.s(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 31:
                    z = false;
                    AbstractC3855z1.y(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 32:
                    z = false;
                    AbstractC3855z1.z(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 33:
                    z = false;
                    AbstractC3855z1.a(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 34:
                    z = false;
                    AbstractC3855z1.b(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 35:
                    AbstractC3855z1.r(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 36:
                    AbstractC3855z1.v(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 37:
                    AbstractC3855z1.x(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 38:
                    AbstractC3855z1.d(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 39:
                    AbstractC3855z1.w(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case RequestError.NETWORK_FAILURE /* 40 */:
                    AbstractC3855z1.u(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case RequestError.NO_DEV_KEY /* 41 */:
                    AbstractC3855z1.t(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 42:
                    AbstractC3855z1.q(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 43:
                    AbstractC3855z1.c(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 44:
                    AbstractC3855z1.s(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 45:
                    AbstractC3855z1.y(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 46:
                    AbstractC3855z1.z(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 47:
                    AbstractC3855z1.a(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 48:
                    AbstractC3855z1.b(iArr[i5], (List) unsafe.getObject(obj, j2), c3817m1, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 49:
                    int i18 = iArr[i5];
                    List list4 = (List) unsafe.getObject(obj, j2);
                    InterfaceC3852y1 interfaceC3852y1A2 = c3831r1.A(i5);
                    C3781a1 c3781a14 = AbstractC3855z1.a;
                    if (list4 != null && !list4.isEmpty()) {
                        for (int i19 = 0; i19 < list4.size(); i19++) {
                            c3817m1.a(i18, list4.get(i19), interfaceC3852y1A2);
                        }
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                    break;
                case RequestError.RESPONSE_CODE_FAILURE /* 50 */:
                    if (unsafe.getObject(obj, j2) != null) {
                        int i20 = i5 / 3;
                        throw androidx.compose.animation.d0.l(c3831r1.b[i20 + i20]);
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 51:
                    if (c3831r1.r(i7, i5, obj)) {
                        ((V0) c3817m1.a).T(i7, Double.doubleToRawLongBits(((Double) G1.g(j2, obj)).doubleValue()));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 52:
                    if (c3831r1.r(i7, i5, obj)) {
                        ((V0) c3817m1.a).R(i7, Float.floatToRawIntBits(((Float) G1.g(j2, obj)).floatValue()));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 53:
                    if (c3831r1.r(i7, i5, obj)) {
                        ((V0) c3817m1.a).b0(i7, y(j2, obj));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 54:
                    if (c3831r1.r(i7, i5, obj)) {
                        ((V0) c3817m1.a).b0(i7, y(j2, obj));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 55:
                    if (c3831r1.r(i7, i5, obj)) {
                        ((V0) c3817m1.a).V(i7, u(j2, obj));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 56:
                    if (c3831r1.r(i7, i5, obj)) {
                        ((V0) c3817m1.a).T(i7, y(j2, obj));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 57:
                    if (c3831r1.r(i7, i5, obj)) {
                        ((V0) c3817m1.a).R(i7, u(j2, obj));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 58:
                    if (c3831r1.r(i7, i5, obj)) {
                        byte bBooleanValue = ((Boolean) G1.g(j2, obj)).booleanValue();
                        V0 v02 = (V0) c3817m1.a;
                        v02.a0(i7 << 3);
                        int i21 = v02.e;
                        try {
                            int i22 = i21 + 1;
                            try {
                                v02.c[i21] = bBooleanValue;
                                v02.e = i22;
                            } catch (IndexOutOfBoundsException e3) {
                                e = e3;
                                i21 = i22;
                                throw new zzgp(i21, v02.d, 1, e);
                            }
                        } catch (IndexOutOfBoundsException e4) {
                            e = e4;
                        }
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 59:
                    if (c3831r1.r(i7, i5, obj)) {
                        Object object2 = unsafe.getObject(obj, j2);
                        if (object2 instanceof String) {
                            ((V0) c3817m1.a).X(i7, (String) object2);
                        } else {
                            ((V0) c3817m1.a).Q(i7, (U0) object2);
                        }
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 60:
                    if (c3831r1.r(i7, i5, obj)) {
                        c3817m1.b(i7, unsafe.getObject(obj, j2), c3831r1.A(i5));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 61:
                    if (c3831r1.r(i7, i5, obj)) {
                        ((V0) c3817m1.a).Q(i7, (U0) unsafe.getObject(obj, j2));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 62:
                    if (c3831r1.r(i7, i5, obj)) {
                        ((V0) c3817m1.a).Z(i7, u(j2, obj));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 63:
                    if (c3831r1.r(i7, i5, obj)) {
                        ((V0) c3817m1.a).V(i7, u(j2, obj));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 64:
                    if (c3831r1.r(i7, i5, obj)) {
                        ((V0) c3817m1.a).R(i7, u(j2, obj));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 65:
                    if (c3831r1.r(i7, i5, obj)) {
                        ((V0) c3817m1.a).T(i7, y(j2, obj));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 66:
                    if (c3831r1.r(i7, i5, obj)) {
                        int iU = u(j2, obj);
                        ((V0) c3817m1.a).Z(i7, (iU >> 31) ^ (iU + iU));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 67:
                    if (c3831r1.r(i7, i5, obj)) {
                        long jY = y(j2, obj);
                        ((V0) c3817m1.a).b0(i7, (jY + jY) ^ (jY >> 63));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                case 68:
                    if (c3831r1.r(i7, i5, obj)) {
                        c3817m1.a(i7, unsafe.getObject(obj, j2), c3831r1.A(i5));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
                default:
                    i5 += 3;
                    i3 = 1048575;
                    c3831r1 = this;
            }
        }
    }

    public final void i(int i, Object obj, Object obj2) {
        if (o(i, obj2)) {
            int iX = x(i) & 1048575;
            Unsafe unsafe = k;
            long j2 = iX;
            Object object = unsafe.getObject(obj2, j2);
            if (object == null) {
                throw new IllegalStateException("Source subfield " + this.a[i] + " is present but null: " + obj2.toString());
            }
            InterfaceC3852y1 interfaceC3852y1A = A(i);
            if (!o(i, obj)) {
                if (q(object)) {
                    AbstractC3787c1 abstractC3787c1Zze = interfaceC3852y1A.zze();
                    interfaceC3852y1A.b(abstractC3787c1Zze, object);
                    unsafe.putObject(obj, j2, abstractC3787c1Zze);
                } else {
                    unsafe.putObject(obj, j2, object);
                }
                k(i, obj);
                return;
            }
            Object object2 = unsafe.getObject(obj, j2);
            if (!q(object2)) {
                AbstractC3787c1 abstractC3787c1Zze2 = interfaceC3852y1A.zze();
                interfaceC3852y1A.b(abstractC3787c1Zze2, object2);
                unsafe.putObject(obj, j2, abstractC3787c1Zze2);
                object2 = abstractC3787c1Zze2;
            }
            interfaceC3852y1A.b(object2, object);
        }
    }

    public final void j(int i, Object obj, Object obj2) {
        int[] iArr = this.a;
        int i2 = iArr[i];
        if (r(i2, i, obj2)) {
            int iX = x(i) & 1048575;
            Unsafe unsafe = k;
            long j2 = iX;
            Object object = unsafe.getObject(obj2, j2);
            if (object == null) {
                throw new IllegalStateException("Source subfield " + iArr[i] + " is present but null: " + obj2.toString());
            }
            InterfaceC3852y1 interfaceC3852y1A = A(i);
            if (!r(i2, i, obj)) {
                if (q(object)) {
                    AbstractC3787c1 abstractC3787c1Zze = interfaceC3852y1A.zze();
                    interfaceC3852y1A.b(abstractC3787c1Zze, object);
                    unsafe.putObject(obj, j2, abstractC3787c1Zze);
                } else {
                    unsafe.putObject(obj, j2, object);
                }
                G1.i(iArr[i + 2] & 1048575, obj, i2);
                return;
            }
            Object object2 = unsafe.getObject(obj, j2);
            if (!q(object2)) {
                AbstractC3787c1 abstractC3787c1Zze2 = interfaceC3852y1A.zze();
                interfaceC3852y1A.b(abstractC3787c1Zze2, object2);
                unsafe.putObject(obj, j2, abstractC3787c1Zze2);
                object2 = abstractC3787c1Zze2;
            }
            interfaceC3852y1A.b(object2, object);
        }
    }

    public final void k(int i, Object obj) {
        int i2 = this.a[i + 2];
        long j2 = 1048575 & i2;
        if (j2 == 1048575) {
            return;
        }
        G1.i(j2, obj, (1 << (i2 >>> 20)) | G1.d(j2, obj));
    }

    public final void l(int i, Object obj, Object obj2) {
        k.putObject(obj, x(i) & 1048575, obj2);
        k(i, obj);
    }

    public final void m(Object obj, int i, Object obj2, int i2) {
        k.putObject(obj, x(i2) & 1048575, obj2);
        G1.i(this.a[i2 + 2] & 1048575, obj, i);
    }

    public final boolean n(AbstractC3787c1 abstractC3787c1, AbstractC3787c1 abstractC3787c12, int i) {
        return o(i, abstractC3787c1) == o(i, abstractC3787c12);
    }

    public final boolean o(int i, Object obj) {
        int i2 = this.a[i + 2];
        long j2 = i2 & 1048575;
        if (j2 == 1048575) {
            int iX = x(i);
            long j3 = iX & 1048575;
            switch (w(iX)) {
                case 0:
                    if (Double.doubleToRawLongBits(G1.c.a(j3, obj)) == 0) {
                        return false;
                    }
                    break;
                case 1:
                    if (Float.floatToRawIntBits(G1.c.b(j3, obj)) == 0) {
                        return false;
                    }
                    break;
                case 2:
                    if (G1.e(j3, obj) == 0) {
                        return false;
                    }
                    break;
                case 3:
                    if (G1.e(j3, obj) == 0) {
                        return false;
                    }
                    break;
                case 4:
                    if (G1.d(j3, obj) == 0) {
                        return false;
                    }
                    break;
                case 5:
                    if (G1.e(j3, obj) == 0) {
                        return false;
                    }
                    break;
                case 6:
                    if (G1.d(j3, obj) == 0) {
                        return false;
                    }
                    break;
                case 7:
                    return G1.c.g(j3, obj);
                case 8:
                    Object objG = G1.g(j3, obj);
                    if (objG instanceof String) {
                        if (((String) objG).isEmpty()) {
                            return false;
                        }
                    } else {
                        if (!(objG instanceof U0)) {
                            throw new IllegalArgumentException();
                        }
                        if (U0.c.equals(objG)) {
                            return false;
                        }
                    }
                    break;
                case 9:
                    if (G1.g(j3, obj) == null) {
                        return false;
                    }
                    break;
                case 10:
                    if (U0.c.equals(G1.g(j3, obj))) {
                        return false;
                    }
                    break;
                case 11:
                    if (G1.d(j3, obj) == 0) {
                        return false;
                    }
                    break;
                case 12:
                    if (G1.d(j3, obj) == 0) {
                        return false;
                    }
                    break;
                case 13:
                    if (G1.d(j3, obj) == 0) {
                        return false;
                    }
                    break;
                case 14:
                    if (G1.e(j3, obj) == 0) {
                        return false;
                    }
                    break;
                case 15:
                    if (G1.d(j3, obj) == 0) {
                        return false;
                    }
                    break;
                case 16:
                    if (G1.e(j3, obj) == 0) {
                        return false;
                    }
                    break;
                case 17:
                    if (G1.g(j3, obj) == null) {
                        return false;
                    }
                    break;
                default:
                    throw new IllegalArgumentException();
            }
        } else if (((1 << (i2 >>> 20)) & G1.d(j2, obj)) == 0) {
            return false;
        }
        return true;
    }

    public final boolean p(Object obj, int i, int i2, int i3, int i4) {
        return i2 == 1048575 ? o(i, obj) : (i3 & i4) != 0;
    }

    public final boolean r(int i, int i2, Object obj) {
        return G1.d((long) (this.a[i2 + 2] & 1048575), obj) == i;
    }

    /* JADX WARN: Code restructure failed: missing block: B:111:0x02f3, code lost:
    
        throw new com.google.android.gms.internal.play_billing.zzhr("Protocol message had invalid UTF-8.");
     */
    /* JADX WARN: Code restructure failed: missing block: B:132:0x034e, code lost:
    
        throw new com.google.android.gms.internal.play_billing.zzhr("Protocol message had invalid UTF-8.");
     */
    /* JADX WARN: Code restructure failed: missing block: B:147:0x03ba, code lost:
    
        throw new com.google.android.gms.internal.play_billing.zzhr("Protocol message had invalid UTF-8.");
     */
    /* JADX WARN: Code restructure failed: missing block: B:168:0x0431, code lost:
    
        r14 = r5;
        r7 = r10;
        r10 = r1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:183:0x04ad, code lost:
    
        r3 = r10;
        r16 = r12;
        r6 = r14;
     */
    /* JADX WARN: Code restructure failed: missing block: B:184:0x04b1, code lost:
    
        r9 = r32;
     */
    /* JADX WARN: Code restructure failed: missing block: B:190:0x04da, code lost:
    
        r11 = r41;
        r5 = r42;
     */
    /* JADX WARN: Code restructure failed: missing block: B:197:0x0526, code lost:
    
        r1 = r7;
     */
    /* JADX WARN: Code restructure failed: missing block: B:201:0x0555, code lost:
    
        r11 = r41;
        r3 = r6;
        r17 = r7;
        r2 = r9;
        r16 = r12;
        r6 = r14;
        r8 = r19;
        r27 = r22;
        r15 = r32;
        r14 = r1;
        r1 = r10;
        r10 = r43;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x0105, code lost:
    
        r13 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x0146, code lost:
    
        r7 = r1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x0147, code lost:
    
        r1 = r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:514:0x0c17, code lost:
    
        r10 = r43;
        r3 = r0;
        r1 = r2;
        r2 = r19;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x0184, code lost:
    
        r10 = r7;
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x0185, code lost:
    
        r7 = r1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x0186, code lost:
    
        r1 = r11;
     */
    /* JADX WARN: Code restructure failed: missing block: B:71:0x01d9, code lost:
    
        r22 = r2;
        r14 = r10;
        r19 = r13;
        r13 = false;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:512:0x0bfd  */
    /* JADX WARN: Removed duplicated region for block: B:612:0x0e95 A[PHI: r1 r2 r5 r28
  0x0e95: PHI (r1v98 byte[]) = 
  (r1v68 byte[])
  (r1v69 byte[])
  (r1v70 byte[])
  (r1v71 byte[])
  (r1v72 byte[])
  (r1v74 byte[])
  (r1v75 byte[])
  (r1v76 byte[])
  (r1v99 byte[])
 binds: [B:610:0x0e7d, B:607:0x0e61, B:604:0x0e49, B:601:0x0e32, B:598:0x0e1b, B:594:0x0e01, B:587:0x0de0, B:573:0x0da5, B:537:0x0c97] A[DONT_GENERATE, DONT_INLINE]
  0x0e95: PHI (r2v118 com.google.android.gms.internal.play_billing.B1) = 
  (r2v97 com.google.android.gms.internal.play_billing.B1)
  (r2v98 com.google.android.gms.internal.play_billing.B1)
  (r2v99 com.google.android.gms.internal.play_billing.B1)
  (r2v100 com.google.android.gms.internal.play_billing.B1)
  (r2v101 com.google.android.gms.internal.play_billing.B1)
  (r2v103 com.google.android.gms.internal.play_billing.B1)
  (r2v104 com.google.android.gms.internal.play_billing.B1)
  (r2v105 com.google.android.gms.internal.play_billing.B1)
  (r2v119 com.google.android.gms.internal.play_billing.B1)
 binds: [B:610:0x0e7d, B:607:0x0e61, B:604:0x0e49, B:601:0x0e32, B:598:0x0e1b, B:594:0x0e01, B:587:0x0de0, B:573:0x0da5, B:537:0x0c97] A[DONT_GENERATE, DONT_INLINE]
  0x0e95: PHI (r5v85 int) = (r5v57 int), (r5v58 int), (r5v59 int), (r5v60 int), (r5v61 int), (r5v63 int), (r5v64 int), (r5v65 int), (r5v86 int) binds: [B:610:0x0e7d, B:607:0x0e61, B:604:0x0e49, B:601:0x0e32, B:598:0x0e1b, B:594:0x0e01, B:587:0x0de0, B:573:0x0da5, B:537:0x0c97] A[DONT_GENERATE, DONT_INLINE]
  0x0e95: PHI (r28v14 int) = (r28v3 int), (r28v3 int), (r28v3 int), (r28v3 int), (r28v3 int), (r28v3 int), (r28v3 int), (r28v3 int), (r28v15 int) binds: [B:610:0x0e7d, B:607:0x0e61, B:604:0x0e49, B:601:0x0e32, B:598:0x0e1b, B:594:0x0e01, B:587:0x0de0, B:573:0x0da5, B:537:0x0c97] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:614:0x0e98  */
    /* JADX WARN: Removed duplicated region for block: B:734:0x0eb0 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:736:0x0c17 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:95:0x02a7  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int s(java.lang.Object r39, byte[] r40, int r41, int r42, int r43, com.google.android.gms.internal.ads.C2776wA r44) {
        /*
            Method dump skipped, instructions count: 4088
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.play_billing.C3831r1.s(java.lang.Object, byte[], int, int, int, com.google.android.gms.internal.ads.wA):int");
    }

    public final int v(int i, int i2) {
        int[] iArr = this.a;
        int length = (iArr.length / 3) - 1;
        while (i2 <= length) {
            int i3 = (length + i2) >>> 1;
            int i4 = i3 * 3;
            int i5 = iArr[i4];
            if (i == i5) {
                return i4;
            }
            if (i < i5) {
                length = i3 - 1;
            } else {
                i2 = i3 + 1;
            }
        }
        return -1;
    }

    public final int x(int i) {
        return this.a[i + 1];
    }

    public final InterfaceC3793e1 z(int i) {
        int i2 = i / 3;
        return (InterfaceC3793e1) this.b[i2 + i2 + 1];
    }

    @Override // com.google.android.gms.internal.play_billing.InterfaceC3852y1
    public final AbstractC3787c1 zze() {
        return (AbstractC3787c1) ((AbstractC3787c1) this.e).d(4);
    }
}
