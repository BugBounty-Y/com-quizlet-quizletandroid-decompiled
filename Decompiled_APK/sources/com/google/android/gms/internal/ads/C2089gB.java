package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.core.view.AbstractC1047f0;
import com.appsflyer.attribution.RequestError;
import com.comscore.streaming.EventType;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;
import sun.misc.Unsafe;

/* renamed from: com.google.android.gms.internal.ads.gB, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2089gB implements InterfaceC2562rB {
    public static final int[] k = new int[0];
    public static final Unsafe l = AbstractC2906zB.j();
    public final int[] a;
    public final Object[] b;
    public final int c;
    public final int d;
    public final AbstractC2647tA e;
    public final boolean f;
    public final int[] g;
    public final int h;
    public final int i;
    public final C1 j;

    public C2089gB(int[] iArr, Object[] objArr, int i, int i2, AbstractC2647tA abstractC2647tA, int[] iArr2, int i3, int i4, C1 c1, C2806wy c2806wy) {
        this.a = iArr;
        this.b = objArr;
        this.c = i;
        this.d = i2;
        this.f = abstractC2647tA instanceof OA;
        this.g = iArr2;
        this.h = i3;
        this.i = i4;
        this.j = c1;
        this.e = abstractC2647tA;
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
    public static com.google.android.gms.internal.ads.C2089gB A(com.google.android.gms.internal.ads.C2391nB r34, com.google.android.gms.internal.ads.C1 r35, com.google.android.gms.internal.ads.C2806wy r36) {
        /*
            Method dump skipped, instructions count: 1048
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2089gB.A(com.google.android.gms.internal.ads.nB, com.google.android.gms.internal.ads.C1, com.google.android.gms.internal.ads.wy):com.google.android.gms.internal.ads.gB");
    }

    public static int B(long j, Object obj) {
        return ((Integer) AbstractC2906zB.i(j, obj)).intValue();
    }

    public static int D(int i) {
        return (i >>> 20) & 255;
    }

    public static long F(long j, Object obj) {
        return ((Long) AbstractC2906zB.i(j, obj)).longValue();
    }

    public static Field l(Class cls, String str) {
        try {
            return cls.getDeclaredField(str);
        } catch (NoSuchFieldException e) {
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
            throw new RuntimeException(sbH.toString(), e);
        }
    }

    public static void m(Object obj) {
        if (!x(obj)) {
            throw new IllegalArgumentException("Mutating immutable message: ".concat(String.valueOf(obj)));
        }
    }

    public static boolean x(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj instanceof OA) {
            return ((OA) obj).r();
        }
        return true;
    }

    public final int C(int i, int i2) {
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

    public final int E(int i) {
        return this.a[i + 1];
    }

    public final RA G(int i) {
        int i2 = i / 3;
        return (RA) this.b[i2 + i2 + 1];
    }

    public final InterfaceC2562rB H(int i) {
        int i2 = i / 3;
        int i3 = i2 + i2;
        Object[] objArr = this.b;
        InterfaceC2562rB interfaceC2562rB = (InterfaceC2562rB) objArr[i3];
        if (interfaceC2562rB != null) {
            return interfaceC2562rB;
        }
        InterfaceC2562rB interfaceC2562rBA = C2305lB.c.a((Class) objArr[i3 + 1]);
        objArr[i3] = interfaceC2562rBA;
        return interfaceC2562rBA;
    }

    public final void I(int i, Object obj, Object obj2) {
        int i2 = this.a[i];
        Object objI = AbstractC2906zB.i(E(i) & 1048575, obj);
        if (objI == null || G(i) == null) {
            return;
        }
        J(i).getClass();
        throw new ClassCastException();
    }

    public final Object J(int i) {
        int i2 = i / 3;
        return this.b[i2 + i2];
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x0074  */
    @Override // com.google.android.gms.internal.ads.InterfaceC2562rB
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(java.lang.Object r8) {
        /*
            r7 = this;
            boolean r0 = x(r8)
            if (r0 != 0) goto L8
            goto L99
        L8:
            boolean r0 = r8 instanceof com.google.android.gms.internal.ads.OA
            r1 = 0
            if (r0 == 0) goto L1b
            r0 = r8
            com.google.android.gms.internal.ads.OA r0 = (com.google.android.gms.internal.ads.OA) r0
            r2 = 2147483647(0x7fffffff, float:NaN)
            r0.f(r2)
            r0.zzq = r1
            r0.j()
        L1b:
            r0 = r1
        L1c:
            int[] r2 = r7.a
            int r3 = r2.length
            if (r0 >= r3) goto L8a
            int r3 = r7.E(r0)
            r4 = 1048575(0xfffff, float:1.469367E-39)
            r4 = r4 & r3
            int r3 = D(r3)
            long r4 = (long) r4
            r6 = 9
            if (r3 == r6) goto L74
            r6 = 60
            if (r3 == r6) goto L5e
            r6 = 68
            if (r3 == r6) goto L5e
            switch(r3) {
                case 17: goto L74;
                case 18: goto L4f;
                case 19: goto L4f;
                case 20: goto L4f;
                case 21: goto L4f;
                case 22: goto L4f;
                case 23: goto L4f;
                case 24: goto L4f;
                case 25: goto L4f;
                case 26: goto L4f;
                case 27: goto L4f;
                case 28: goto L4f;
                case 29: goto L4f;
                case 30: goto L4f;
                case 31: goto L4f;
                case 32: goto L4f;
                case 33: goto L4f;
                case 34: goto L4f;
                case 35: goto L4f;
                case 36: goto L4f;
                case 37: goto L4f;
                case 38: goto L4f;
                case 39: goto L4f;
                case 40: goto L4f;
                case 41: goto L4f;
                case 42: goto L4f;
                case 43: goto L4f;
                case 44: goto L4f;
                case 45: goto L4f;
                case 46: goto L4f;
                case 47: goto L4f;
                case 48: goto L4f;
                case 49: goto L4f;
                case 50: goto L3e;
                default: goto L3d;
            }
        L3d:
            goto L87
        L3e:
            sun.misc.Unsafe r2 = com.google.android.gms.internal.ads.C2089gB.l
            java.lang.Object r3 = r2.getObject(r8, r4)
            if (r3 == 0) goto L87
            r6 = r3
            com.google.android.gms.internal.ads.bB r6 = (com.google.android.gms.internal.ads.C1871bB) r6
            r6.a = r1
            r2.putObject(r8, r4, r3)
            goto L87
        L4f:
            java.lang.Object r2 = com.google.android.gms.internal.ads.AbstractC2906zB.i(r4, r8)
            com.google.android.gms.internal.ads.VA r2 = (com.google.android.gms.internal.ads.VA) r2
            com.google.android.gms.internal.ads.uA r2 = (com.google.android.gms.internal.ads.AbstractC2690uA) r2
            boolean r3 = r2.a
            if (r3 == 0) goto L87
            r2.a = r1
            goto L87
        L5e:
            r2 = r2[r0]
            boolean r2 = r7.y(r2, r0, r8)
            if (r2 == 0) goto L87
            com.google.android.gms.internal.ads.rB r2 = r7.H(r0)
            sun.misc.Unsafe r3 = com.google.android.gms.internal.ads.C2089gB.l
            java.lang.Object r3 = r3.getObject(r8, r4)
            r2.a(r3)
            goto L87
        L74:
            boolean r2 = r7.v(r0, r8)
            if (r2 == 0) goto L87
            com.google.android.gms.internal.ads.rB r2 = r7.H(r0)
            sun.misc.Unsafe r3 = com.google.android.gms.internal.ads.C2089gB.l
            java.lang.Object r3 = r3.getObject(r8, r4)
            r2.a(r3)
        L87:
            int r0 = r0 + 3
            goto L1c
        L8a:
            com.google.android.gms.internal.ads.C1 r0 = r7.j
            r0.getClass()
            com.google.android.gms.internal.ads.OA r8 = (com.google.android.gms.internal.ads.OA) r8
            com.google.android.gms.internal.ads.uB r8 = r8.zzt
            boolean r0 = r8.e
            if (r0 == 0) goto L99
            r8.e = r1
        L99:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2089gB.a(java.lang.Object):void");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:7:0x001e  */
    @Override // com.google.android.gms.internal.ads.InterfaceC2562rB
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(java.lang.Object r11, java.lang.Object r12) {
        /*
            Method dump skipped, instructions count: 594
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2089gB.b(java.lang.Object, java.lang.Object):void");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2562rB
    public final void c(Object obj, byte[] bArr, int i, int i2, C2776wA c2776wA) {
        z(obj, bArr, i, i2, 0, c2776wA);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2562rB
    public final boolean d(Object obj) {
        int i;
        int i2;
        int i3;
        int i4 = 0;
        int i5 = 0;
        int i6 = 1048575;
        while (i5 < this.h) {
            int i7 = this.g[i5];
            int[] iArr = this.a;
            int i8 = iArr[i7];
            int iE = E(i7);
            int i9 = iArr[i7 + 2];
            int i10 = i9 & 1048575;
            int i11 = 1 << (i9 >>> 20);
            if (i10 != i6) {
                if (i10 != 1048575) {
                    i4 = l.getInt(obj, i10);
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
            if ((268435456 & iE) == 0 || w(obj, i2, i, i3, i11)) {
                int iD = D(iE);
                if (iD != 9 && iD != 17) {
                    if (iD != 27) {
                        if (iD == 60 || iD == 68) {
                            if (!y(i8, i2, obj) || H(i2).d(AbstractC2906zB.i(iE & 1048575, obj))) {
                            }
                        } else if (iD != 49) {
                            if (iD == 50 && !((C1871bB) AbstractC2906zB.i(iE & 1048575, obj)).isEmpty()) {
                                J(i2).getClass();
                                throw new ClassCastException();
                            }
                        }
                        i5++;
                        i6 = i;
                        i4 = i3;
                    }
                    List list = (List) AbstractC2906zB.i(iE & 1048575, obj);
                    if (list.isEmpty()) {
                        continue;
                    } else {
                        InterfaceC2562rB interfaceC2562rBH = H(i2);
                        for (int i13 = 0; i13 < list.size(); i13++) {
                            if (interfaceC2562rBH.d(list.get(i13))) {
                            }
                        }
                    }
                    i5++;
                    i6 = i;
                    i4 = i3;
                } else if (!w(obj, i2, i, i3, i11) || H(i2).d(AbstractC2906zB.i(iE & 1048575, obj))) {
                    i5++;
                    i6 = i;
                    i4 = i3;
                }
            }
            return false;
        }
        return true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2562rB
    public final void e(Object obj, C2586rt c2586rt) {
        int i;
        C2089gB c2089gB = this;
        Unsafe unsafe = l;
        int i2 = 1048575;
        int i3 = 0;
        int i4 = 0;
        int i5 = 1048575;
        while (true) {
            int[] iArr = c2089gB.a;
            if (i3 >= iArr.length) {
                ((OA) obj).zzt.d(c2586rt);
                return;
            }
            int iE = c2089gB.E(i3);
            int iD = D(iE);
            int i6 = iArr[i3];
            if (iD <= 17) {
                int i7 = iArr[i3 + 2];
                int i8 = i7 & i2;
                if (i8 != i5) {
                    i4 = i8 == i2 ? 0 : unsafe.getInt(obj, i8);
                    i5 = i8;
                }
                i = 1 << (i7 >>> 20);
            } else {
                i = 0;
            }
            long j = iE & i2;
            switch (iD) {
                case 0:
                    if (c2089gB.w(obj, i3, i5, i4, i)) {
                        ((HA) c2586rt.b).K(i6, Double.doubleToRawLongBits(AbstractC2906zB.c.W0(j, obj)));
                        break;
                    } else {
                        break;
                    }
                case 1:
                    if (c2089gB.w(obj, i3, i5, i4, i)) {
                        ((HA) c2586rt.b).I(i6, Float.floatToRawIntBits(AbstractC2906zB.c.Y0(j, obj)));
                        break;
                    } else {
                        break;
                    }
                case 2:
                    if (c2089gB.w(obj, i3, i5, i4, i)) {
                        ((HA) c2586rt.b).T(i6, unsafe.getLong(obj, j));
                        break;
                    } else {
                        break;
                    }
                case 3:
                    if (c2089gB.w(obj, i3, i5, i4, i)) {
                        ((HA) c2586rt.b).T(i6, unsafe.getLong(obj, j));
                        break;
                    } else {
                        break;
                    }
                case 4:
                    if (c2089gB.w(obj, i3, i5, i4, i)) {
                        ((HA) c2586rt.b).M(i6, unsafe.getInt(obj, j));
                        break;
                    } else {
                        break;
                    }
                case 5:
                    if (c2089gB.w(obj, i3, i5, i4, i)) {
                        ((HA) c2586rt.b).K(i6, unsafe.getLong(obj, j));
                        break;
                    } else {
                        break;
                    }
                case 6:
                    if (c2089gB.w(obj, i3, i5, i4, i)) {
                        ((HA) c2586rt.b).I(i6, unsafe.getInt(obj, j));
                        break;
                    } else {
                        break;
                    }
                case 7:
                    if (c2089gB.w(obj, i3, i5, i4, i)) {
                        ((HA) c2586rt.b).G(i6, AbstractC2906zB.c.g1(j, obj));
                        break;
                    } else {
                        break;
                    }
                case 8:
                    if (c2089gB.w(obj, i3, i5, i4, i)) {
                        Object object = unsafe.getObject(obj, j);
                        if (object instanceof String) {
                            ((HA) c2586rt.b).P(i6, (String) object);
                            break;
                        } else {
                            ((HA) c2586rt.b).H(i6, (BA) object);
                            break;
                        }
                    } else {
                        break;
                    }
                case 9:
                    if (c2089gB.w(obj, i3, i5, i4, i)) {
                        Object object2 = unsafe.getObject(obj, j);
                        InterfaceC2562rB interfaceC2562rBH = c2089gB.H(i3);
                        c2586rt.getClass();
                        ((HA) c2586rt.b).O(i6, (AbstractC2647tA) object2, interfaceC2562rBH);
                        break;
                    } else {
                        break;
                    }
                case 10:
                    if (c2089gB.w(obj, i3, i5, i4, i)) {
                        ((HA) c2586rt.b).H(i6, (BA) unsafe.getObject(obj, j));
                        break;
                    } else {
                        break;
                    }
                case 11:
                    if (c2089gB.w(obj, i3, i5, i4, i)) {
                        ((HA) c2586rt.b).R(i6, unsafe.getInt(obj, j));
                        break;
                    } else {
                        break;
                    }
                case 12:
                    if (c2089gB.w(obj, i3, i5, i4, i)) {
                        ((HA) c2586rt.b).M(i6, unsafe.getInt(obj, j));
                        break;
                    } else {
                        break;
                    }
                case 13:
                    if (c2089gB.w(obj, i3, i5, i4, i)) {
                        ((HA) c2586rt.b).I(i6, unsafe.getInt(obj, j));
                        break;
                    } else {
                        break;
                    }
                case 14:
                    if (c2089gB.w(obj, i3, i5, i4, i)) {
                        ((HA) c2586rt.b).K(i6, unsafe.getLong(obj, j));
                        break;
                    } else {
                        break;
                    }
                case 15:
                    if (c2089gB.w(obj, i3, i5, i4, i)) {
                        int i9 = unsafe.getInt(obj, j);
                        ((HA) c2586rt.b).R(i6, (i9 >> 31) ^ (i9 + i9));
                        break;
                    } else {
                        break;
                    }
                case 16:
                    if (c2089gB.w(obj, i3, i5, i4, i)) {
                        long j2 = unsafe.getLong(obj, j);
                        ((HA) c2586rt.b).T(i6, (j2 + j2) ^ (j2 >> 63));
                        break;
                    } else {
                        break;
                    }
                case 17:
                    if (c2089gB.w(obj, i3, i5, i4, i)) {
                        c2586rt.c(i6, unsafe.getObject(obj, j), c2089gB.H(i3));
                        break;
                    } else {
                        break;
                    }
                case 18:
                    AbstractC2605sB.u(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, false);
                    break;
                case 19:
                    AbstractC2605sB.y(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, false);
                    break;
                case 20:
                    AbstractC2605sB.a(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, false);
                    break;
                case 21:
                    AbstractC2605sB.g(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, false);
                    break;
                case EventType.WINDOW_STATE /* 22 */:
                    AbstractC2605sB.z(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, false);
                    break;
                case EventType.AUDIO /* 23 */:
                    AbstractC2605sB.x(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, false);
                    break;
                case EventType.VIDEO /* 24 */:
                    AbstractC2605sB.w(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, false);
                    break;
                case EventType.SUBS /* 25 */:
                    AbstractC2605sB.t(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, false);
                    break;
                case EventType.CDN /* 26 */:
                    int i10 = iArr[i3];
                    List list = (List) unsafe.getObject(obj, j);
                    C1 c1 = AbstractC2605sB.a;
                    if (list != null && !list.isEmpty()) {
                        c2586rt.getClass();
                        for (int i11 = 0; i11 < list.size(); i11++) {
                            ((HA) c2586rt.b).P(i10, (String) list.get(i11));
                        }
                        break;
                    } else {
                        break;
                    }
                    break;
                case 27:
                    int i12 = iArr[i3];
                    List list2 = (List) unsafe.getObject(obj, j);
                    InterfaceC2562rB interfaceC2562rBH2 = c2089gB.H(i3);
                    C1 c12 = AbstractC2605sB.a;
                    if (list2 != null && !list2.isEmpty()) {
                        for (int i13 = 0; i13 < list2.size(); i13++) {
                            Object obj2 = list2.get(i13);
                            c2586rt.getClass();
                            ((HA) c2586rt.b).O(i12, (AbstractC2647tA) obj2, interfaceC2562rBH2);
                        }
                        break;
                    } else {
                        break;
                    }
                    break;
                case 28:
                    int i14 = iArr[i3];
                    List list3 = (List) unsafe.getObject(obj, j);
                    C1 c13 = AbstractC2605sB.a;
                    if (list3 != null && !list3.isEmpty()) {
                        c2586rt.getClass();
                        for (int i15 = 0; i15 < list3.size(); i15++) {
                            ((HA) c2586rt.b).H(i14, (BA) list3.get(i15));
                        }
                        break;
                    } else {
                        break;
                    }
                case 29:
                    AbstractC2605sB.f(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, false);
                    break;
                case 30:
                    AbstractC2605sB.v(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, false);
                    break;
                case 31:
                    AbstractC2605sB.b(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, false);
                    break;
                case 32:
                    AbstractC2605sB.c(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, false);
                    break;
                case 33:
                    AbstractC2605sB.d(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, false);
                    break;
                case 34:
                    AbstractC2605sB.e(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, false);
                    break;
                case 35:
                    AbstractC2605sB.u(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, true);
                    break;
                case 36:
                    AbstractC2605sB.y(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, true);
                    break;
                case 37:
                    AbstractC2605sB.a(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, true);
                    break;
                case 38:
                    AbstractC2605sB.g(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, true);
                    break;
                case 39:
                    AbstractC2605sB.z(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, true);
                    break;
                case RequestError.NETWORK_FAILURE /* 40 */:
                    AbstractC2605sB.x(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, true);
                    break;
                case RequestError.NO_DEV_KEY /* 41 */:
                    AbstractC2605sB.w(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, true);
                    break;
                case 42:
                    AbstractC2605sB.t(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, true);
                    break;
                case 43:
                    AbstractC2605sB.f(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, true);
                    break;
                case 44:
                    AbstractC2605sB.v(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, true);
                    break;
                case 45:
                    AbstractC2605sB.b(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, true);
                    break;
                case 46:
                    AbstractC2605sB.c(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, true);
                    break;
                case 47:
                    AbstractC2605sB.d(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, true);
                    break;
                case 48:
                    AbstractC2605sB.e(iArr[i3], (List) unsafe.getObject(obj, j), c2586rt, true);
                    break;
                case 49:
                    int i16 = iArr[i3];
                    List list4 = (List) unsafe.getObject(obj, j);
                    InterfaceC2562rB interfaceC2562rBH3 = c2089gB.H(i3);
                    C1 c14 = AbstractC2605sB.a;
                    if (list4 != null && !list4.isEmpty()) {
                        for (int i17 = 0; i17 < list4.size(); i17++) {
                            c2586rt.c(i16, list4.get(i17), interfaceC2562rBH3);
                        }
                        break;
                    } else {
                        break;
                    }
                    break;
                case RequestError.RESPONSE_CODE_FAILURE /* 50 */:
                    if (unsafe.getObject(obj, j) != null) {
                        c2089gB.J(i3).getClass();
                        throw new ClassCastException();
                    }
                    break;
                case 51:
                    if (c2089gB.y(i6, i3, obj)) {
                        ((HA) c2586rt.b).K(i6, Double.doubleToRawLongBits(((Double) AbstractC2906zB.i(j, obj)).doubleValue()));
                        break;
                    } else {
                        break;
                    }
                case 52:
                    if (c2089gB.y(i6, i3, obj)) {
                        ((HA) c2586rt.b).I(i6, Float.floatToRawIntBits(((Float) AbstractC2906zB.i(j, obj)).floatValue()));
                        break;
                    } else {
                        break;
                    }
                case 53:
                    if (c2089gB.y(i6, i3, obj)) {
                        ((HA) c2586rt.b).T(i6, F(j, obj));
                        break;
                    } else {
                        break;
                    }
                case 54:
                    if (c2089gB.y(i6, i3, obj)) {
                        ((HA) c2586rt.b).T(i6, F(j, obj));
                        break;
                    } else {
                        break;
                    }
                case 55:
                    if (c2089gB.y(i6, i3, obj)) {
                        ((HA) c2586rt.b).M(i6, B(j, obj));
                        break;
                    } else {
                        break;
                    }
                case 56:
                    if (c2089gB.y(i6, i3, obj)) {
                        ((HA) c2586rt.b).K(i6, F(j, obj));
                        break;
                    } else {
                        break;
                    }
                case 57:
                    if (c2089gB.y(i6, i3, obj)) {
                        ((HA) c2586rt.b).I(i6, B(j, obj));
                        break;
                    } else {
                        break;
                    }
                case 58:
                    if (c2089gB.y(i6, i3, obj)) {
                        ((HA) c2586rt.b).G(i6, ((Boolean) AbstractC2906zB.i(j, obj)).booleanValue());
                        break;
                    } else {
                        break;
                    }
                case 59:
                    if (c2089gB.y(i6, i3, obj)) {
                        Object object3 = unsafe.getObject(obj, j);
                        if (object3 instanceof String) {
                            ((HA) c2586rt.b).P(i6, (String) object3);
                            break;
                        } else {
                            ((HA) c2586rt.b).H(i6, (BA) object3);
                            break;
                        }
                    } else {
                        break;
                    }
                case 60:
                    if (c2089gB.y(i6, i3, obj)) {
                        Object object4 = unsafe.getObject(obj, j);
                        InterfaceC2562rB interfaceC2562rBH4 = c2089gB.H(i3);
                        c2586rt.getClass();
                        ((HA) c2586rt.b).O(i6, (AbstractC2647tA) object4, interfaceC2562rBH4);
                        break;
                    } else {
                        break;
                    }
                case 61:
                    if (c2089gB.y(i6, i3, obj)) {
                        ((HA) c2586rt.b).H(i6, (BA) unsafe.getObject(obj, j));
                        break;
                    } else {
                        break;
                    }
                case 62:
                    if (c2089gB.y(i6, i3, obj)) {
                        ((HA) c2586rt.b).R(i6, B(j, obj));
                        break;
                    } else {
                        break;
                    }
                case 63:
                    if (c2089gB.y(i6, i3, obj)) {
                        ((HA) c2586rt.b).M(i6, B(j, obj));
                        break;
                    } else {
                        break;
                    }
                case 64:
                    if (c2089gB.y(i6, i3, obj)) {
                        ((HA) c2586rt.b).I(i6, B(j, obj));
                        break;
                    } else {
                        break;
                    }
                case 65:
                    if (c2089gB.y(i6, i3, obj)) {
                        ((HA) c2586rt.b).K(i6, F(j, obj));
                        break;
                    } else {
                        break;
                    }
                case 66:
                    if (c2089gB.y(i6, i3, obj)) {
                        int iB = B(j, obj);
                        ((HA) c2586rt.b).R(i6, (iB >> 31) ^ (iB + iB));
                        break;
                    } else {
                        break;
                    }
                case 67:
                    if (c2089gB.y(i6, i3, obj)) {
                        long jF = F(j, obj);
                        ((HA) c2586rt.b).T(i6, (jF + jF) ^ (jF >> 63));
                        break;
                    } else {
                        break;
                    }
                case 68:
                    if (c2089gB.y(i6, i3, obj)) {
                        c2586rt.c(i6, unsafe.getObject(obj, j), c2089gB.H(i3));
                        break;
                    } else {
                        break;
                    }
            }
            i3 += 3;
            i2 = 1048575;
            c2089gB = this;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:44:0x00db A[PHI: r1
  0x00db: PHI (r1v34 int) = (r1v10 int), (r1v35 int) binds: [B:85:0x01ea, B:43:0x00d9] A[DONT_GENERATE, DONT_INLINE]] */
    @Override // com.google.android.gms.internal.ads.InterfaceC2562rB
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int f(com.google.android.gms.internal.ads.OA r11) {
        /*
            Method dump skipped, instructions count: 726
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2089gB.f(com.google.android.gms.internal.ads.OA):int");
    }

    /* JADX WARN: Removed duplicated region for block: B:142:0x03bd  */
    /* JADX WARN: Removed duplicated region for block: B:186:0x04d8  */
    @Override // com.google.android.gms.internal.ads.InterfaceC2562rB
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int g(com.google.android.gms.internal.ads.OA r18) {
        /*
            Method dump skipped, instructions count: 1944
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2089gB.g(com.google.android.gms.internal.ads.OA):int");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2562rB
    public final boolean h(OA oa, OA oa2) {
        boolean zH;
        int i = 0;
        while (true) {
            int[] iArr = this.a;
            if (i < iArr.length) {
                int iE = E(i);
                long j = iE & 1048575;
                switch (D(iE)) {
                    case 0:
                        if (!u(oa, oa2, i)) {
                            break;
                        } else {
                            AbstractC2863yB abstractC2863yB = AbstractC2906zB.c;
                            if (Double.doubleToLongBits(abstractC2863yB.W0(j, oa)) != Double.doubleToLongBits(abstractC2863yB.W0(j, oa2))) {
                                break;
                            } else {
                                continue;
                                i += 3;
                            }
                        }
                    case 1:
                        if (!u(oa, oa2, i)) {
                            break;
                        } else {
                            AbstractC2863yB abstractC2863yB2 = AbstractC2906zB.c;
                            if (Float.floatToIntBits(abstractC2863yB2.Y0(j, oa)) != Float.floatToIntBits(abstractC2863yB2.Y0(j, oa2))) {
                                break;
                            } else {
                                continue;
                                i += 3;
                            }
                        }
                    case 2:
                        if (!u(oa, oa2, i) || AbstractC2906zB.g(j, oa) != AbstractC2906zB.g(j, oa2)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 3:
                        if (!u(oa, oa2, i) || AbstractC2906zB.g(j, oa) != AbstractC2906zB.g(j, oa2)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 4:
                        if (!u(oa, oa2, i) || AbstractC2906zB.e(j, oa) != AbstractC2906zB.e(j, oa2)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 5:
                        if (!u(oa, oa2, i) || AbstractC2906zB.g(j, oa) != AbstractC2906zB.g(j, oa2)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 6:
                        if (!u(oa, oa2, i) || AbstractC2906zB.e(j, oa) != AbstractC2906zB.e(j, oa2)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 7:
                        if (!u(oa, oa2, i)) {
                            break;
                        } else {
                            AbstractC2863yB abstractC2863yB3 = AbstractC2906zB.c;
                            if (abstractC2863yB3.g1(j, oa) != abstractC2863yB3.g1(j, oa2)) {
                                break;
                            } else {
                                continue;
                                i += 3;
                            }
                        }
                    case 8:
                        if (!u(oa, oa2, i) || !AbstractC2605sB.h(AbstractC2906zB.i(j, oa), AbstractC2906zB.i(j, oa2))) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 9:
                        if (!u(oa, oa2, i) || !AbstractC2605sB.h(AbstractC2906zB.i(j, oa), AbstractC2906zB.i(j, oa2))) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 10:
                        if (!u(oa, oa2, i) || !AbstractC2605sB.h(AbstractC2906zB.i(j, oa), AbstractC2906zB.i(j, oa2))) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 11:
                        if (!u(oa, oa2, i) || AbstractC2906zB.e(j, oa) != AbstractC2906zB.e(j, oa2)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 12:
                        if (!u(oa, oa2, i) || AbstractC2906zB.e(j, oa) != AbstractC2906zB.e(j, oa2)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 13:
                        if (!u(oa, oa2, i) || AbstractC2906zB.e(j, oa) != AbstractC2906zB.e(j, oa2)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 14:
                        if (!u(oa, oa2, i) || AbstractC2906zB.g(j, oa) != AbstractC2906zB.g(j, oa2)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 15:
                        if (!u(oa, oa2, i) || AbstractC2906zB.e(j, oa) != AbstractC2906zB.e(j, oa2)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 16:
                        if (!u(oa, oa2, i) || AbstractC2906zB.g(j, oa) != AbstractC2906zB.g(j, oa2)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 17:
                        if (!u(oa, oa2, i) || !AbstractC2605sB.h(AbstractC2906zB.i(j, oa), AbstractC2906zB.i(j, oa2))) {
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
                        zH = AbstractC2605sB.h(AbstractC2906zB.i(j, oa), AbstractC2906zB.i(j, oa2));
                        break;
                    case RequestError.RESPONSE_CODE_FAILURE /* 50 */:
                        zH = AbstractC2605sB.h(AbstractC2906zB.i(j, oa), AbstractC2906zB.i(j, oa2));
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
                        long j2 = iArr[i + 2] & 1048575;
                        if (AbstractC2906zB.e(j2, oa) != AbstractC2906zB.e(j2, oa2) || !AbstractC2605sB.h(AbstractC2906zB.i(j, oa), AbstractC2906zB.i(j, oa2))) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    default:
                        i += 3;
                }
                if (zH) {
                    i += 3;
                }
            } else if (oa.zzt.equals(oa2.zzt)) {
                return true;
            }
        }
        return false;
    }

    /*  JADX ERROR: Type inference failed
        jadx.core.utils.exceptions.JadxOverflowException: Type inference error: updates count limit reached
        	at jadx.core.utils.ErrorsCounter.addError(ErrorsCounter.java:59)
        	at jadx.core.utils.ErrorsCounter.error(ErrorsCounter.java:31)
        	at jadx.core.dex.attributes.nodes.NotificationAttrNode.addError(NotificationAttrNode.java:19)
        	at jadx.core.dex.visitors.typeinference.TypeInferenceVisitor.visit(TypeInferenceVisitor.java:77)
        */
    @Override // com.google.android.gms.internal.ads.InterfaceC2562rB
    public final void i(java.lang.Object r27, androidx.compose.runtime.changelist.K r28, com.google.android.gms.internal.ads.IA r29) {
        /*
            Method dump skipped, instructions count: 2090
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2089gB.i(java.lang.Object, androidx.compose.runtime.changelist.K, com.google.android.gms.internal.ads.IA):void");
    }

    public final Object j(int i, Object obj) {
        InterfaceC2562rB interfaceC2562rBH = H(i);
        int iE = E(i) & 1048575;
        if (!v(i, obj)) {
            return interfaceC2562rBH.zze();
        }
        Object object = l.getObject(obj, iE);
        if (x(object)) {
            return object;
        }
        OA oaZze = interfaceC2562rBH.zze();
        if (object != null) {
            interfaceC2562rBH.b(oaZze, object);
        }
        return oaZze;
    }

    public final Object k(int i, int i2, Object obj) {
        InterfaceC2562rB interfaceC2562rBH = H(i2);
        if (!y(i, i2, obj)) {
            return interfaceC2562rBH.zze();
        }
        Object object = l.getObject(obj, E(i2) & 1048575);
        if (x(object)) {
            return object;
        }
        OA oaZze = interfaceC2562rBH.zze();
        if (object != null) {
            interfaceC2562rBH.b(oaZze, object);
        }
        return oaZze;
    }

    public final void n(int i, Object obj, Object obj2) {
        if (v(i, obj2)) {
            int iE = E(i) & 1048575;
            Unsafe unsafe = l;
            long j = iE;
            Object object = unsafe.getObject(obj2, j);
            if (object == null) {
                throw new IllegalStateException("Source subfield " + this.a[i] + " is present but null: " + obj2.toString());
            }
            InterfaceC2562rB interfaceC2562rBH = H(i);
            if (!v(i, obj)) {
                if (x(object)) {
                    OA oaZze = interfaceC2562rBH.zze();
                    interfaceC2562rBH.b(oaZze, object);
                    unsafe.putObject(obj, j, oaZze);
                } else {
                    unsafe.putObject(obj, j, object);
                }
                q(i, obj);
                return;
            }
            Object object2 = unsafe.getObject(obj, j);
            if (!x(object2)) {
                OA oaZze2 = interfaceC2562rBH.zze();
                interfaceC2562rBH.b(oaZze2, object2);
                unsafe.putObject(obj, j, oaZze2);
                object2 = oaZze2;
            }
            interfaceC2562rBH.b(object2, object);
        }
    }

    public final void o(int i, Object obj, Object obj2) {
        int[] iArr = this.a;
        int i2 = iArr[i];
        if (y(i2, i, obj2)) {
            int iE = E(i) & 1048575;
            Unsafe unsafe = l;
            long j = iE;
            Object object = unsafe.getObject(obj2, j);
            if (object == null) {
                throw new IllegalStateException("Source subfield " + iArr[i] + " is present but null: " + obj2.toString());
            }
            InterfaceC2562rB interfaceC2562rBH = H(i);
            if (!y(i2, i, obj)) {
                if (x(object)) {
                    OA oaZze = interfaceC2562rBH.zze();
                    interfaceC2562rBH.b(oaZze, object);
                    unsafe.putObject(obj, j, oaZze);
                } else {
                    unsafe.putObject(obj, j, object);
                }
                r(i2, i, obj);
                return;
            }
            Object object2 = unsafe.getObject(obj, j);
            if (!x(object2)) {
                OA oaZze2 = interfaceC2562rBH.zze();
                interfaceC2562rBH.b(oaZze2, object2);
                unsafe.putObject(obj, j, oaZze2);
                object2 = oaZze2;
            }
            interfaceC2562rBH.b(object2, object);
        }
    }

    public final void p(int i, androidx.compose.runtime.changelist.K k2, Object obj) {
        long j = i & 1048575;
        if ((536870912 & i) != 0) {
            k2.y(2);
            AbstractC2906zB.n(j, obj, ((AbstractC1047f0) k2.e).g0());
        } else if (this.f) {
            k2.y(2);
            AbstractC2906zB.n(j, obj, ((AbstractC1047f0) k2.e).f0());
        } else {
            k2.y(2);
            AbstractC2906zB.n(j, obj, ((AbstractC1047f0) k2.e).e0());
        }
    }

    public final void q(int i, Object obj) {
        int i2 = this.a[i + 2];
        long j = 1048575 & i2;
        if (j == 1048575) {
            return;
        }
        AbstractC2906zB.l(j, obj, (1 << (i2 >>> 20)) | AbstractC2906zB.e(j, obj));
    }

    public final void r(int i, int i2, Object obj) {
        AbstractC2906zB.l(this.a[i2 + 2] & 1048575, obj, i);
    }

    public final void s(int i, Object obj, Object obj2) {
        l.putObject(obj, E(i) & 1048575, obj2);
        q(i, obj);
    }

    public final void t(Object obj, int i, Object obj2, int i2) {
        l.putObject(obj, E(i2) & 1048575, obj2);
        r(i, i2, obj);
    }

    public final boolean u(OA oa, OA oa2, int i) {
        return v(i, oa) == v(i, oa2);
    }

    public final boolean v(int i, Object obj) {
        int i2 = this.a[i + 2];
        long j = i2 & 1048575;
        if (j == 1048575) {
            int iE = E(i);
            long j2 = iE & 1048575;
            switch (D(iE)) {
                case 0:
                    if (Double.doubleToRawLongBits(AbstractC2906zB.c.W0(j2, obj)) == 0) {
                        return false;
                    }
                    break;
                case 1:
                    if (Float.floatToRawIntBits(AbstractC2906zB.c.Y0(j2, obj)) == 0) {
                        return false;
                    }
                    break;
                case 2:
                    if (AbstractC2906zB.g(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 3:
                    if (AbstractC2906zB.g(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 4:
                    if (AbstractC2906zB.e(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 5:
                    if (AbstractC2906zB.g(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 6:
                    if (AbstractC2906zB.e(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 7:
                    return AbstractC2906zB.c.g1(j2, obj);
                case 8:
                    Object objI = AbstractC2906zB.i(j2, obj);
                    if (objI instanceof String) {
                        if (((String) objI).isEmpty()) {
                            return false;
                        }
                    } else {
                        if (!(objI instanceof BA)) {
                            throw new IllegalArgumentException();
                        }
                        if (BA.b.equals(objI)) {
                            return false;
                        }
                    }
                    break;
                case 9:
                    if (AbstractC2906zB.i(j2, obj) == null) {
                        return false;
                    }
                    break;
                case 10:
                    if (BA.b.equals(AbstractC2906zB.i(j2, obj))) {
                        return false;
                    }
                    break;
                case 11:
                    if (AbstractC2906zB.e(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 12:
                    if (AbstractC2906zB.e(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 13:
                    if (AbstractC2906zB.e(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 14:
                    if (AbstractC2906zB.g(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 15:
                    if (AbstractC2906zB.e(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 16:
                    if (AbstractC2906zB.g(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 17:
                    if (AbstractC2906zB.i(j2, obj) == null) {
                        return false;
                    }
                    break;
                default:
                    throw new IllegalArgumentException();
            }
        } else if (((1 << (i2 >>> 20)) & AbstractC2906zB.e(j, obj)) == 0) {
            return false;
        }
        return true;
    }

    public final boolean w(Object obj, int i, int i2, int i3, int i4) {
        return i2 == 1048575 ? v(i, obj) : (i3 & i4) != 0;
    }

    public final boolean y(int i, int i2, Object obj) {
        return AbstractC2906zB.e((long) (this.a[i2 + 2] & 1048575), obj) == i;
    }

    /* JADX WARN: Code restructure failed: missing block: B:113:0x02d3, code lost:
    
        r9 = r10;
        r8 = r12;
        r3 = r13;
        r6 = r15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:126:0x0345, code lost:
    
        r1 = r9;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x00d9, code lost:
    
        r3 = r9;
        r9 = r10;
        r6 = r11;
        r8 = r12;
     */
    /* JADX WARN: Code restructure failed: missing block: B:51:0x0136, code lost:
    
        r5 = r37;
        r3 = r9;
        r9 = r10;
        r6 = r11;
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x013b, code lost:
    
        r8 = r12;
        r2 = r13;
     */
    /* JADX WARN: Code restructure failed: missing block: B:95:0x023a, code lost:
    
        r5 = r37;
        r3 = r1;
        r14 = r2;
        r1 = r9;
        r9 = r10;
        r8 = r12;
        r2 = r13;
     */
    /* JADX WARN: Code restructure failed: missing block: B:96:0x0242, code lost:
    
        r15 = r18;
     */
    /* JADX WARN: Removed duplicated region for block: B:518:0x0cce A[PHI: r3 r4 r8 r9 r12 r15 r18
  0x0cce: PHI (r3v143 com.google.android.gms.internal.ads.wA) = 
  (r3v115 com.google.android.gms.internal.ads.wA)
  (r3v116 com.google.android.gms.internal.ads.wA)
  (r3v117 com.google.android.gms.internal.ads.wA)
  (r3v118 com.google.android.gms.internal.ads.wA)
  (r3v119 com.google.android.gms.internal.ads.wA)
  (r3v120 com.google.android.gms.internal.ads.wA)
  (r3v121 com.google.android.gms.internal.ads.wA)
  (r3v122 com.google.android.gms.internal.ads.wA)
  (r3v125 com.google.android.gms.internal.ads.wA)
  (r3v132 com.google.android.gms.internal.ads.wA)
  (r3v139 com.google.android.gms.internal.ads.wA)
  (r3v144 com.google.android.gms.internal.ads.wA)
 binds: [B:516:0x0cb7, B:513:0x0c93, B:510:0x0c73, B:507:0x0c53, B:504:0x0c33, B:501:0x0c12, B:494:0x0bea, B:480:0x0baa, B:478:0x0b8f, B:455:0x0ae0, B:449:0x0aaf, B:443:0x0a76] A[DONT_GENERATE, DONT_INLINE]
  0x0cce: PHI (r4v156 byte[]) = 
  (r4v127 byte[])
  (r4v128 byte[])
  (r4v129 byte[])
  (r4v130 byte[])
  (r4v131 byte[])
  (r4v132 byte[])
  (r4v133 byte[])
  (r4v134 byte[])
  (r4v136 byte[])
  (r4v143 byte[])
  (r4v152 byte[])
  (r4v157 byte[])
 binds: [B:516:0x0cb7, B:513:0x0c93, B:510:0x0c73, B:507:0x0c53, B:504:0x0c33, B:501:0x0c12, B:494:0x0bea, B:480:0x0baa, B:478:0x0b8f, B:455:0x0ae0, B:449:0x0aaf, B:443:0x0a76] A[DONT_GENERATE, DONT_INLINE]
  0x0cce: PHI (r8v77 com.google.android.gms.internal.ads.uB) = 
  (r8v55 com.google.android.gms.internal.ads.uB)
  (r8v56 com.google.android.gms.internal.ads.uB)
  (r8v57 com.google.android.gms.internal.ads.uB)
  (r8v58 com.google.android.gms.internal.ads.uB)
  (r8v59 com.google.android.gms.internal.ads.uB)
  (r8v60 com.google.android.gms.internal.ads.uB)
  (r8v61 com.google.android.gms.internal.ads.uB)
  (r8v62 com.google.android.gms.internal.ads.uB)
  (r8v63 com.google.android.gms.internal.ads.uB)
  (r8v70 com.google.android.gms.internal.ads.uB)
  (r8v74 com.google.android.gms.internal.ads.uB)
  (r8v78 com.google.android.gms.internal.ads.uB)
 binds: [B:516:0x0cb7, B:513:0x0c93, B:510:0x0c73, B:507:0x0c53, B:504:0x0c33, B:501:0x0c12, B:494:0x0bea, B:480:0x0baa, B:478:0x0b8f, B:455:0x0ae0, B:449:0x0aaf, B:443:0x0a76] A[DONT_GENERATE, DONT_INLINE]
  0x0cce: PHI (r9v120 sun.misc.Unsafe) = 
  (r9v97 sun.misc.Unsafe)
  (r9v98 sun.misc.Unsafe)
  (r9v99 sun.misc.Unsafe)
  (r9v100 sun.misc.Unsafe)
  (r9v101 sun.misc.Unsafe)
  (r9v102 sun.misc.Unsafe)
  (r9v103 sun.misc.Unsafe)
  (r9v104 sun.misc.Unsafe)
  (r9v105 sun.misc.Unsafe)
  (r9v110 sun.misc.Unsafe)
  (r9v116 sun.misc.Unsafe)
  (r9v121 sun.misc.Unsafe)
 binds: [B:516:0x0cb7, B:513:0x0c93, B:510:0x0c73, B:507:0x0c53, B:504:0x0c33, B:501:0x0c12, B:494:0x0bea, B:480:0x0baa, B:478:0x0b8f, B:455:0x0ae0, B:449:0x0aaf, B:443:0x0a76] A[DONT_GENERATE, DONT_INLINE]
  0x0cce: PHI (r12v19 int) = 
  (r12v4 int)
  (r12v5 int)
  (r12v6 int)
  (r12v7 int)
  (r12v8 int)
  (r12v9 int)
  (r12v10 int)
  (r12v11 int)
  (r12v12 int)
  (r12v14 int)
  (r12v16 int)
  (r12v20 int)
 binds: [B:516:0x0cb7, B:513:0x0c93, B:510:0x0c73, B:507:0x0c53, B:504:0x0c33, B:501:0x0c12, B:494:0x0bea, B:480:0x0baa, B:478:0x0b8f, B:455:0x0ae0, B:449:0x0aaf, B:443:0x0a76] A[DONT_GENERATE, DONT_INLINE]
  0x0cce: PHI (r15v101 int) = 
  (r15v78 int)
  (r15v79 int)
  (r15v80 int)
  (r15v81 int)
  (r15v82 int)
  (r15v83 int)
  (r15v84 int)
  (r15v85 int)
  (r15v86 int)
  (r15v91 int)
  (r15v97 int)
  (r15v102 int)
 binds: [B:516:0x0cb7, B:513:0x0c93, B:510:0x0c73, B:507:0x0c53, B:504:0x0c33, B:501:0x0c12, B:494:0x0bea, B:480:0x0baa, B:478:0x0b8f, B:455:0x0ae0, B:449:0x0aaf, B:443:0x0a76] A[DONT_GENERATE, DONT_INLINE]
  0x0cce: PHI (r18v79 int) = 
  (r18v63 int)
  (r18v64 int)
  (r18v65 int)
  (r18v66 int)
  (r18v67 int)
  (r18v68 int)
  (r18v69 int)
  (r18v70 int)
  (r18v72 int)
  (r18v75 int)
  (r18v77 int)
  (r18v80 int)
 binds: [B:516:0x0cb7, B:513:0x0c93, B:510:0x0c73, B:507:0x0c53, B:504:0x0c33, B:501:0x0c12, B:494:0x0bea, B:480:0x0baa, B:478:0x0b8f, B:455:0x0ae0, B:449:0x0aaf, B:443:0x0a76] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:585:0x0cd1 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:601:0x09e4 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:623:0x09f8 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:624:0x0ce7 A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int z(java.lang.Object r34, byte[] r35, int r36, int r37, int r38, com.google.android.gms.internal.ads.C2776wA r39) {
        /*
            Method dump skipped, instructions count: 3572
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2089gB.z(java.lang.Object, byte[], int, int, int, com.google.android.gms.internal.ads.wA):int");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2562rB
    public final OA zze() {
        return ((OA) this.e).n();
    }
}
