package com.google.android.gms.internal.measurement;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.appsflyer.attribution.RequestError;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.ads.C2776wA;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;
import sun.misc.Unsafe;

/* renamed from: com.google.android.gms.internal.measurement.o2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3035o2 implements InterfaceC3069v2 {
    public static final int[] j = new int[0];
    public static final Unsafe k = C2.h();
    public final int[] a;
    public final Object[] b;
    public final int c;
    public final int d;
    public final J1 e;
    public final int[] f;
    public final int g;
    public final int h;
    public final U1 i;

    public C3035o2(int[] iArr, Object[] objArr, int i, int i2, J1 j1, int[] iArr2, int i3, int i4, U1 u1, U1 u12) {
        this.a = iArr;
        this.b = objArr;
        this.c = i;
        this.d = i2;
        this.f = iArr2;
        this.g = i3;
        this.h = i4;
        this.i = u1;
        this.e = j1;
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
        if (obj instanceof W1) {
            return ((W1) obj).l();
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
    public static com.google.android.gms.internal.measurement.C3035o2 t(com.google.android.gms.internal.measurement.C3064u2 r34, com.google.android.gms.internal.measurement.U1 r35, com.google.android.gms.internal.measurement.U1 r36) {
        /*
            Method dump skipped, instructions count: 1048
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.measurement.C3035o2.t(com.google.android.gms.internal.measurement.u2, com.google.android.gms.internal.measurement.U1, com.google.android.gms.internal.measurement.U1):com.google.android.gms.internal.measurement.o2");
    }

    public static int u(long j2, Object obj) {
        return ((Integer) C2.g(j2, obj)).intValue();
    }

    public static int w(int i) {
        return (i >>> 20) & 255;
    }

    public static long y(long j2, Object obj) {
        return ((Long) C2.g(j2, obj)).longValue();
    }

    public final InterfaceC3069v2 A(int i) {
        int i2 = i / 3;
        int i3 = i2 + i2;
        Object[] objArr = this.b;
        InterfaceC3069v2 interfaceC3069v2 = (InterfaceC3069v2) objArr[i3];
        if (interfaceC3069v2 != null) {
            return interfaceC3069v2;
        }
        InterfaceC3069v2 interfaceC3069v2A = C3054s2.c.a((Class) objArr[i3 + 1]);
        objArr[i3] = interfaceC3069v2A;
        return interfaceC3069v2A;
    }

    public final Object B(int i, Object obj) {
        InterfaceC3069v2 interfaceC3069v2A = A(i);
        int iX = x(i) & 1048575;
        if (!o(i, obj)) {
            return interfaceC3069v2A.zze();
        }
        Object object = k.getObject(obj, iX);
        if (q(object)) {
            return object;
        }
        W1 w1Zze = interfaceC3069v2A.zze();
        if (object != null) {
            interfaceC3069v2A.b(w1Zze, object);
        }
        return w1Zze;
    }

    public final Object C(int i, int i2, Object obj) {
        InterfaceC3069v2 interfaceC3069v2A = A(i2);
        if (!r(i, i2, obj)) {
            return interfaceC3069v2A.zze();
        }
        Object object = k.getObject(obj, x(i2) & 1048575);
        if (q(object)) {
            return object;
        }
        W1 w1Zze = interfaceC3069v2A.zze();
        if (object != null) {
            interfaceC3069v2A.b(w1Zze, object);
        }
        return w1Zze;
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x0071  */
    @Override // com.google.android.gms.internal.measurement.InterfaceC3069v2
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
            boolean r0 = r8 instanceof com.google.android.gms.internal.measurement.W1
            r1 = 0
            if (r0 == 0) goto L18
            r0 = r8
            com.google.android.gms.internal.measurement.W1 r0 = (com.google.android.gms.internal.measurement.W1) r0
            r0.k()
            r0.zza = r1
            r0.i()
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
            sun.misc.Unsafe r2 = com.google.android.gms.internal.measurement.C3035o2.k
            java.lang.Object r3 = r2.getObject(r8, r4)
            if (r3 == 0) goto L84
            r6 = r3
            com.google.android.gms.internal.measurement.k2 r6 = (com.google.android.gms.internal.measurement.C3015k2) r6
            r6.a = r1
            r2.putObject(r8, r4, r3)
            goto L84
        L4c:
            java.lang.Object r2 = com.google.android.gms.internal.measurement.C2.g(r4, r8)
            com.google.android.gms.internal.measurement.c2 r2 = (com.google.android.gms.internal.measurement.InterfaceC2975c2) r2
            com.google.android.gms.internal.measurement.K1 r2 = (com.google.android.gms.internal.measurement.K1) r2
            boolean r3 = r2.a
            if (r3 == 0) goto L84
            r2.a = r1
            goto L84
        L5b:
            r2 = r2[r0]
            boolean r2 = r7.r(r2, r0, r8)
            if (r2 == 0) goto L84
            com.google.android.gms.internal.measurement.v2 r2 = r7.A(r0)
            sun.misc.Unsafe r3 = com.google.android.gms.internal.measurement.C3035o2.k
            java.lang.Object r3 = r3.getObject(r8, r4)
            r2.a(r3)
            goto L84
        L71:
            boolean r2 = r7.o(r0, r8)
            if (r2 == 0) goto L84
            com.google.android.gms.internal.measurement.v2 r2 = r7.A(r0)
            sun.misc.Unsafe r3 = com.google.android.gms.internal.measurement.C3035o2.k
            java.lang.Object r3 = r3.getObject(r8, r4)
            r2.a(r3)
        L84:
            int r0 = r0 + 3
            goto L19
        L87:
            com.google.android.gms.internal.measurement.U1 r0 = r7.i
            r0.getClass()
            com.google.android.gms.internal.measurement.W1 r8 = (com.google.android.gms.internal.measurement.W1) r8
            com.google.android.gms.internal.measurement.x2 r8 = r8.zzc
            boolean r0 = r8.e
            if (r0 == 0) goto L96
            r8.e = r1
        L96:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.measurement.C3035o2.a(java.lang.Object):void");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:9:0x0022  */
    @Override // com.google.android.gms.internal.measurement.InterfaceC3069v2
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(java.lang.Object r13, java.lang.Object r14) {
        /*
            Method dump skipped, instructions count: 628
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.measurement.C3035o2.b(java.lang.Object, java.lang.Object):void");
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3069v2
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
                            if (!r(i8, i2, obj) || A(i2).c(C2.g(iX & 1048575, obj))) {
                            }
                        } else if (iW != 49) {
                            if (iW == 50 && !((C3015k2) C2.g(iX & 1048575, obj)).isEmpty()) {
                                int i13 = i2 / 3;
                                throw androidx.compose.animation.d0.l(this.b[i13 + i13]);
                            }
                        }
                        i5++;
                        i6 = i;
                        i4 = i3;
                    }
                    List list = (List) C2.g(iX & 1048575, obj);
                    if (list.isEmpty()) {
                        continue;
                    } else {
                        InterfaceC3069v2 interfaceC3069v2A = A(i2);
                        for (int i14 = 0; i14 < list.size(); i14++) {
                            if (interfaceC3069v2A.c(list.get(i14))) {
                            }
                        }
                    }
                    i5++;
                    i6 = i;
                    i4 = i3;
                } else if (!p(obj, i2, i, i3, i11) || A(i2).c(C2.g(iX & 1048575, obj))) {
                    i5++;
                    i6 = i;
                    i4 = i3;
                }
            }
            return false;
        }
        return true;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    @Override // com.google.android.gms.internal.measurement.InterfaceC3069v2
    public final void d(Object obj, C3005i2 c3005i2) throws zzli {
        int i;
        int i2;
        boolean z;
        C3035o2 c3035o2 = this;
        Unsafe unsafe = k;
        int i3 = 1048575;
        int i4 = 1048575;
        int i5 = 0;
        int i6 = 0;
        while (true) {
            int[] iArr = c3035o2.a;
            if (i5 >= iArr.length) {
                ((W1) obj).zzc.d(c3005i2);
                return;
            }
            int iX = c3035o2.x(i5);
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
                    if (c3035o2.p(obj, i5, i4, i6, i)) {
                        ((P1) c3005i2.a).f(i7, Double.doubleToRawLongBits(C2.c.a(j2, obj)));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 1:
                    if (c3035o2.p(obj, i5, i4, i6, i)) {
                        ((P1) c3005i2.a).d(i7, Float.floatToRawIntBits(C2.c.b(j2, obj)));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 2:
                    if (c3035o2.p(obj, i5, i4, i6, i)) {
                        ((P1) c3005i2.a).n(i7, unsafe.getLong(obj, j2));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 3:
                    if (c3035o2.p(obj, i5, i4, i6, i)) {
                        ((P1) c3005i2.a).n(i7, unsafe.getLong(obj, j2));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 4:
                    if (c3035o2.p(obj, i5, i4, i6, i)) {
                        ((P1) c3005i2.a).h(i7, unsafe.getInt(obj, j2));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 5:
                    if (c3035o2.p(obj, i5, i4, i6, i)) {
                        ((P1) c3005i2.a).f(i7, unsafe.getLong(obj, j2));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 6:
                    if (c3035o2.p(obj, i5, i4, i6, i)) {
                        ((P1) c3005i2.a).d(i7, unsafe.getInt(obj, j2));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 7:
                    if (c3035o2.p(obj, i5, i4, i6, i)) {
                        byte bG = C2.c.g(j2, obj);
                        P1 p1 = (P1) c3005i2.a;
                        p1.m(i7 << 3);
                        int i10 = p1.e;
                        try {
                            i2 = i10 + 1;
                        } catch (IndexOutOfBoundsException e) {
                            e = e;
                        }
                        try {
                            p1.c[i10] = bG;
                            p1.e = i2;
                        } catch (IndexOutOfBoundsException e2) {
                            e = e2;
                            i10 = i2;
                            throw new zzli(i10, p1.d, 1, e);
                        }
                    } else {
                        continue;
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 8:
                    if (c3035o2.p(obj, i5, i4, i6, i)) {
                        Object object = unsafe.getObject(obj, j2);
                        if (object instanceof String) {
                            ((P1) c3005i2.a).j(i7, (String) object);
                        } else {
                            ((P1) c3005i2.a).c(i7, (O1) object);
                        }
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 9:
                    if (c3035o2.p(obj, i5, i4, i6, i)) {
                        c3005i2.e(i7, unsafe.getObject(obj, j2), c3035o2.A(i5));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 10:
                    if (c3035o2.p(obj, i5, i4, i6, i)) {
                        ((P1) c3005i2.a).c(i7, (O1) unsafe.getObject(obj, j2));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 11:
                    if (c3035o2.p(obj, i5, i4, i6, i)) {
                        ((P1) c3005i2.a).l(i7, unsafe.getInt(obj, j2));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 12:
                    if (c3035o2.p(obj, i5, i4, i6, i)) {
                        ((P1) c3005i2.a).h(i7, unsafe.getInt(obj, j2));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 13:
                    if (c3035o2.p(obj, i5, i4, i6, i)) {
                        ((P1) c3005i2.a).d(i7, unsafe.getInt(obj, j2));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 14:
                    if (c3035o2.p(obj, i5, i4, i6, i)) {
                        ((P1) c3005i2.a).f(i7, unsafe.getLong(obj, j2));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 15:
                    if (c3035o2.p(obj, i5, i4, i6, i)) {
                        int i11 = unsafe.getInt(obj, j2);
                        ((P1) c3005i2.a).l(i7, (i11 >> 31) ^ (i11 + i11));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 16:
                    if (c3035o2.p(obj, i5, i4, i6, i)) {
                        long j3 = unsafe.getLong(obj, j2);
                        ((P1) c3005i2.a).n(i7, (j3 + j3) ^ (j3 >> 63));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 17:
                    if (c3035o2.p(obj, i5, i4, i6, i)) {
                        c3005i2.b(i7, unsafe.getObject(obj, j2), c3035o2.A(i5));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 18:
                    AbstractC3074w2.r(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 19:
                    AbstractC3074w2.v(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 20:
                    AbstractC3074w2.x(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 21:
                    AbstractC3074w2.d(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case EventType.WINDOW_STATE /* 22 */:
                    AbstractC3074w2.w(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case EventType.AUDIO /* 23 */:
                    AbstractC3074w2.u(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case EventType.VIDEO /* 24 */:
                    AbstractC3074w2.t(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case EventType.SUBS /* 25 */:
                    AbstractC3074w2.q(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case EventType.CDN /* 26 */:
                    int i12 = iArr[i5];
                    List list = (List) unsafe.getObject(obj, j2);
                    U1 u1 = AbstractC3074w2.a;
                    if (list != null && !list.isEmpty()) {
                        c3005i2.getClass();
                        for (int i13 = 0; i13 < list.size(); i13++) {
                            ((P1) c3005i2.a).j(i12, (String) list.get(i13));
                        }
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                    break;
                case 27:
                    int i14 = iArr[i5];
                    List list2 = (List) unsafe.getObject(obj, j2);
                    InterfaceC3069v2 interfaceC3069v2A = c3035o2.A(i5);
                    U1 u12 = AbstractC3074w2.a;
                    if (list2 != null && !list2.isEmpty()) {
                        for (int i15 = 0; i15 < list2.size(); i15++) {
                            c3005i2.e(i14, list2.get(i15), interfaceC3069v2A);
                        }
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                    break;
                case 28:
                    int i16 = iArr[i5];
                    List list3 = (List) unsafe.getObject(obj, j2);
                    U1 u13 = AbstractC3074w2.a;
                    if (list3 != null && !list3.isEmpty()) {
                        c3005i2.getClass();
                        for (int i17 = 0; i17 < list3.size(); i17++) {
                            ((P1) c3005i2.a).c(i16, (O1) list3.get(i17));
                        }
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                    break;
                case 29:
                    z = false;
                    AbstractC3074w2.c(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 30:
                    z = false;
                    AbstractC3074w2.s(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 31:
                    z = false;
                    AbstractC3074w2.y(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 32:
                    z = false;
                    AbstractC3074w2.z(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 33:
                    z = false;
                    AbstractC3074w2.a(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 34:
                    z = false;
                    AbstractC3074w2.b(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, false);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 35:
                    AbstractC3074w2.r(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 36:
                    AbstractC3074w2.v(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 37:
                    AbstractC3074w2.x(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 38:
                    AbstractC3074w2.d(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 39:
                    AbstractC3074w2.w(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case RequestError.NETWORK_FAILURE /* 40 */:
                    AbstractC3074w2.u(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case RequestError.NO_DEV_KEY /* 41 */:
                    AbstractC3074w2.t(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 42:
                    AbstractC3074w2.q(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 43:
                    AbstractC3074w2.c(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 44:
                    AbstractC3074w2.s(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 45:
                    AbstractC3074w2.y(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 46:
                    AbstractC3074w2.z(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 47:
                    AbstractC3074w2.a(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 48:
                    AbstractC3074w2.b(iArr[i5], (List) unsafe.getObject(obj, j2), c3005i2, true);
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 49:
                    int i18 = iArr[i5];
                    List list4 = (List) unsafe.getObject(obj, j2);
                    InterfaceC3069v2 interfaceC3069v2A2 = c3035o2.A(i5);
                    U1 u14 = AbstractC3074w2.a;
                    if (list4 != null && !list4.isEmpty()) {
                        for (int i19 = 0; i19 < list4.size(); i19++) {
                            c3005i2.b(i18, list4.get(i19), interfaceC3069v2A2);
                        }
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                    break;
                case RequestError.RESPONSE_CODE_FAILURE /* 50 */:
                    if (unsafe.getObject(obj, j2) != null) {
                        int i20 = i5 / 3;
                        throw androidx.compose.animation.d0.l(c3035o2.b[i20 + i20]);
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 51:
                    if (c3035o2.r(i7, i5, obj)) {
                        ((P1) c3005i2.a).f(i7, Double.doubleToRawLongBits(((Double) C2.g(j2, obj)).doubleValue()));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 52:
                    if (c3035o2.r(i7, i5, obj)) {
                        ((P1) c3005i2.a).d(i7, Float.floatToRawIntBits(((Float) C2.g(j2, obj)).floatValue()));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 53:
                    if (c3035o2.r(i7, i5, obj)) {
                        ((P1) c3005i2.a).n(i7, y(j2, obj));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 54:
                    if (c3035o2.r(i7, i5, obj)) {
                        ((P1) c3005i2.a).n(i7, y(j2, obj));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 55:
                    if (c3035o2.r(i7, i5, obj)) {
                        ((P1) c3005i2.a).h(i7, u(j2, obj));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 56:
                    if (c3035o2.r(i7, i5, obj)) {
                        ((P1) c3005i2.a).f(i7, y(j2, obj));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 57:
                    if (c3035o2.r(i7, i5, obj)) {
                        ((P1) c3005i2.a).d(i7, u(j2, obj));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 58:
                    if (c3035o2.r(i7, i5, obj)) {
                        byte bBooleanValue = ((Boolean) C2.g(j2, obj)).booleanValue();
                        P1 p12 = (P1) c3005i2.a;
                        p12.m(i7 << 3);
                        int i21 = p12.e;
                        try {
                            int i22 = i21 + 1;
                            try {
                                p12.c[i21] = bBooleanValue;
                                p12.e = i22;
                            } catch (IndexOutOfBoundsException e3) {
                                e = e3;
                                i21 = i22;
                                throw new zzli(i21, p12.d, 1, e);
                            }
                        } catch (IndexOutOfBoundsException e4) {
                            e = e4;
                        }
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 59:
                    if (c3035o2.r(i7, i5, obj)) {
                        Object object2 = unsafe.getObject(obj, j2);
                        if (object2 instanceof String) {
                            ((P1) c3005i2.a).j(i7, (String) object2);
                        } else {
                            ((P1) c3005i2.a).c(i7, (O1) object2);
                        }
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 60:
                    if (c3035o2.r(i7, i5, obj)) {
                        c3005i2.e(i7, unsafe.getObject(obj, j2), c3035o2.A(i5));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 61:
                    if (c3035o2.r(i7, i5, obj)) {
                        ((P1) c3005i2.a).c(i7, (O1) unsafe.getObject(obj, j2));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 62:
                    if (c3035o2.r(i7, i5, obj)) {
                        ((P1) c3005i2.a).l(i7, u(j2, obj));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 63:
                    if (c3035o2.r(i7, i5, obj)) {
                        ((P1) c3005i2.a).h(i7, u(j2, obj));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 64:
                    if (c3035o2.r(i7, i5, obj)) {
                        ((P1) c3005i2.a).d(i7, u(j2, obj));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 65:
                    if (c3035o2.r(i7, i5, obj)) {
                        ((P1) c3005i2.a).f(i7, y(j2, obj));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 66:
                    if (c3035o2.r(i7, i5, obj)) {
                        int iU = u(j2, obj);
                        ((P1) c3005i2.a).l(i7, (iU >> 31) ^ (iU + iU));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 67:
                    if (c3035o2.r(i7, i5, obj)) {
                        long jY = y(j2, obj);
                        ((P1) c3005i2.a).n(i7, (jY + jY) ^ (jY >> 63));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                case 68:
                    if (c3035o2.r(i7, i5, obj)) {
                        c3005i2.b(i7, unsafe.getObject(obj, j2), c3035o2.A(i5));
                    }
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
                default:
                    i5 += 3;
                    i3 = 1048575;
                    c3035o2 = this;
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:142:0x03c0  */
    /* JADX WARN: Removed duplicated region for block: B:186:0x04db  */
    @Override // com.google.android.gms.internal.measurement.InterfaceC3069v2
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int e(com.google.android.gms.internal.measurement.W1 r18) {
        /*
            Method dump skipped, instructions count: 1946
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.measurement.C3035o2.e(com.google.android.gms.internal.measurement.W1):int");
    }

    /* JADX WARN: Removed duplicated region for block: B:44:0x00db A[PHI: r1
  0x00db: PHI (r1v34 int) = (r1v10 int), (r1v35 int) binds: [B:85:0x01ea, B:43:0x00d9] A[DONT_GENERATE, DONT_INLINE]] */
    @Override // com.google.android.gms.internal.measurement.InterfaceC3069v2
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int f(com.google.android.gms.internal.measurement.W1 r11) {
        /*
            Method dump skipped, instructions count: 726
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.measurement.C3035o2.f(com.google.android.gms.internal.measurement.W1):int");
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3069v2
    public final boolean g(W1 w1, W1 w12) {
        boolean zE;
        int i = 0;
        while (true) {
            int[] iArr = this.a;
            if (i < iArr.length) {
                int iX = x(i);
                long j2 = iX & 1048575;
                switch (w(iX)) {
                    case 0:
                        if (!n(w1, w12, i)) {
                            break;
                        } else {
                            B2 b2 = C2.c;
                            if (Double.doubleToLongBits(b2.a(j2, w1)) != Double.doubleToLongBits(b2.a(j2, w12))) {
                                break;
                            } else {
                                continue;
                                i += 3;
                            }
                        }
                    case 1:
                        if (!n(w1, w12, i)) {
                            break;
                        } else {
                            B2 b22 = C2.c;
                            if (Float.floatToIntBits(b22.b(j2, w1)) != Float.floatToIntBits(b22.b(j2, w12))) {
                                break;
                            } else {
                                continue;
                                i += 3;
                            }
                        }
                    case 2:
                        if (!n(w1, w12, i) || C2.e(j2, w1) != C2.e(j2, w12)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 3:
                        if (!n(w1, w12, i) || C2.e(j2, w1) != C2.e(j2, w12)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 4:
                        if (!n(w1, w12, i) || C2.d(j2, w1) != C2.d(j2, w12)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 5:
                        if (!n(w1, w12, i) || C2.e(j2, w1) != C2.e(j2, w12)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 6:
                        if (!n(w1, w12, i) || C2.d(j2, w1) != C2.d(j2, w12)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 7:
                        if (!n(w1, w12, i)) {
                            break;
                        } else {
                            B2 b23 = C2.c;
                            if (b23.g(j2, w1) != b23.g(j2, w12)) {
                                break;
                            } else {
                                continue;
                                i += 3;
                            }
                        }
                    case 8:
                        if (!n(w1, w12, i) || !AbstractC3074w2.e(C2.g(j2, w1), C2.g(j2, w12))) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 9:
                        if (!n(w1, w12, i) || !AbstractC3074w2.e(C2.g(j2, w1), C2.g(j2, w12))) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 10:
                        if (!n(w1, w12, i) || !AbstractC3074w2.e(C2.g(j2, w1), C2.g(j2, w12))) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 11:
                        if (!n(w1, w12, i) || C2.d(j2, w1) != C2.d(j2, w12)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 12:
                        if (!n(w1, w12, i) || C2.d(j2, w1) != C2.d(j2, w12)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 13:
                        if (!n(w1, w12, i) || C2.d(j2, w1) != C2.d(j2, w12)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 14:
                        if (!n(w1, w12, i) || C2.e(j2, w1) != C2.e(j2, w12)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 15:
                        if (!n(w1, w12, i) || C2.d(j2, w1) != C2.d(j2, w12)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 16:
                        if (!n(w1, w12, i) || C2.e(j2, w1) != C2.e(j2, w12)) {
                            break;
                        } else {
                            continue;
                            i += 3;
                        }
                        break;
                    case 17:
                        if (!n(w1, w12, i) || !AbstractC3074w2.e(C2.g(j2, w1), C2.g(j2, w12))) {
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
                        zE = AbstractC3074w2.e(C2.g(j2, w1), C2.g(j2, w12));
                        break;
                    case RequestError.RESPONSE_CODE_FAILURE /* 50 */:
                        zE = AbstractC3074w2.e(C2.g(j2, w1), C2.g(j2, w12));
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
                        if (C2.d(j3, w1) != C2.d(j3, w12) || !AbstractC3074w2.e(C2.g(j2, w1), C2.g(j2, w12))) {
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
            } else if (w1.zzc.equals(w12.zzc)) {
                return true;
            }
        }
        return false;
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3069v2
    public final void h(Object obj, byte[] bArr, int i, int i2, C2776wA c2776wA) throws zzmm {
        s(obj, bArr, i, i2, 0, c2776wA);
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
            InterfaceC3069v2 interfaceC3069v2A = A(i);
            if (!o(i, obj)) {
                if (q(object)) {
                    W1 w1Zze = interfaceC3069v2A.zze();
                    interfaceC3069v2A.b(w1Zze, object);
                    unsafe.putObject(obj, j2, w1Zze);
                } else {
                    unsafe.putObject(obj, j2, object);
                }
                k(i, obj);
                return;
            }
            Object object2 = unsafe.getObject(obj, j2);
            if (!q(object2)) {
                W1 w1Zze2 = interfaceC3069v2A.zze();
                interfaceC3069v2A.b(w1Zze2, object2);
                unsafe.putObject(obj, j2, w1Zze2);
                object2 = w1Zze2;
            }
            interfaceC3069v2A.b(object2, object);
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
            InterfaceC3069v2 interfaceC3069v2A = A(i);
            if (!r(i2, i, obj)) {
                if (q(object)) {
                    W1 w1Zze = interfaceC3069v2A.zze();
                    interfaceC3069v2A.b(w1Zze, object);
                    unsafe.putObject(obj, j2, w1Zze);
                } else {
                    unsafe.putObject(obj, j2, object);
                }
                C2.i(iArr[i + 2] & 1048575, obj, i2);
                return;
            }
            Object object2 = unsafe.getObject(obj, j2);
            if (!q(object2)) {
                W1 w1Zze2 = interfaceC3069v2A.zze();
                interfaceC3069v2A.b(w1Zze2, object2);
                unsafe.putObject(obj, j2, w1Zze2);
                object2 = w1Zze2;
            }
            interfaceC3069v2A.b(object2, object);
        }
    }

    public final void k(int i, Object obj) {
        int i2 = this.a[i + 2];
        long j2 = 1048575 & i2;
        if (j2 == 1048575) {
            return;
        }
        C2.i(j2, obj, (1 << (i2 >>> 20)) | C2.d(j2, obj));
    }

    public final void l(int i, Object obj, Object obj2) {
        k.putObject(obj, x(i) & 1048575, obj2);
        k(i, obj);
    }

    public final void m(Object obj, int i, Object obj2, int i2) {
        k.putObject(obj, x(i2) & 1048575, obj2);
        C2.i(this.a[i2 + 2] & 1048575, obj, i);
    }

    public final boolean n(W1 w1, W1 w12, int i) {
        return o(i, w1) == o(i, w12);
    }

    public final boolean o(int i, Object obj) {
        int i2 = this.a[i + 2];
        long j2 = i2 & 1048575;
        if (j2 == 1048575) {
            int iX = x(i);
            long j3 = iX & 1048575;
            switch (w(iX)) {
                case 0:
                    if (Double.doubleToRawLongBits(C2.c.a(j3, obj)) == 0) {
                        return false;
                    }
                    break;
                case 1:
                    if (Float.floatToRawIntBits(C2.c.b(j3, obj)) == 0) {
                        return false;
                    }
                    break;
                case 2:
                    if (C2.e(j3, obj) == 0) {
                        return false;
                    }
                    break;
                case 3:
                    if (C2.e(j3, obj) == 0) {
                        return false;
                    }
                    break;
                case 4:
                    if (C2.d(j3, obj) == 0) {
                        return false;
                    }
                    break;
                case 5:
                    if (C2.e(j3, obj) == 0) {
                        return false;
                    }
                    break;
                case 6:
                    if (C2.d(j3, obj) == 0) {
                        return false;
                    }
                    break;
                case 7:
                    return C2.c.g(j3, obj);
                case 8:
                    Object objG = C2.g(j3, obj);
                    if (objG instanceof String) {
                        if (((String) objG).isEmpty()) {
                            return false;
                        }
                    } else {
                        if (!(objG instanceof O1)) {
                            throw new IllegalArgumentException();
                        }
                        if (O1.c.equals(objG)) {
                            return false;
                        }
                    }
                    break;
                case 9:
                    if (C2.g(j3, obj) == null) {
                        return false;
                    }
                    break;
                case 10:
                    if (O1.c.equals(C2.g(j3, obj))) {
                        return false;
                    }
                    break;
                case 11:
                    if (C2.d(j3, obj) == 0) {
                        return false;
                    }
                    break;
                case 12:
                    if (C2.d(j3, obj) == 0) {
                        return false;
                    }
                    break;
                case 13:
                    if (C2.d(j3, obj) == 0) {
                        return false;
                    }
                    break;
                case 14:
                    if (C2.e(j3, obj) == 0) {
                        return false;
                    }
                    break;
                case 15:
                    if (C2.d(j3, obj) == 0) {
                        return false;
                    }
                    break;
                case 16:
                    if (C2.e(j3, obj) == 0) {
                        return false;
                    }
                    break;
                case 17:
                    if (C2.g(j3, obj) == null) {
                        return false;
                    }
                    break;
                default:
                    throw new IllegalArgumentException();
            }
        } else if (((1 << (i2 >>> 20)) & C2.d(j2, obj)) == 0) {
            return false;
        }
        return true;
    }

    public final boolean p(Object obj, int i, int i2, int i3, int i4) {
        return i2 == 1048575 ? o(i, obj) : (i3 & i4) != 0;
    }

    public final boolean r(int i, int i2, Object obj) {
        return C2.d((long) (this.a[i2 + 2] & 1048575), obj) == i;
    }

    /* JADX WARN: Code restructure failed: missing block: B:108:0x02fb, code lost:
    
        throw new com.google.android.gms.internal.measurement.zzmm("Protocol message had invalid UTF-8.");
     */
    /* JADX WARN: Code restructure failed: missing block: B:130:0x0358, code lost:
    
        throw new com.google.android.gms.internal.measurement.zzmm("Protocol message had invalid UTF-8.");
     */
    /* JADX WARN: Code restructure failed: missing block: B:145:0x03c6, code lost:
    
        throw new com.google.android.gms.internal.measurement.zzmm("Protocol message had invalid UTF-8.");
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:123:0x0331  */
    /* JADX WARN: Removed duplicated region for block: B:125:0x0334 A[PHI: r3
  0x0334: PHI (r3v71 byte) = (r3v70 byte), (r3v78 byte) binds: [B:122:0x032f, B:124:0x0333] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:127:0x033a  */
    /* JADX WARN: Removed duplicated region for block: B:617:0x0fba A[PHI: r3 r5 r8 r15 r30
  0x0fba: PHI (r3v183 int) = 
  (r3v155 int)
  (r3v156 int)
  (r3v157 int)
  (r3v158 int)
  (r3v159 int)
  (r3v161 int)
  (r3v162 int)
  (r3v163 int)
  (r3v168 int)
  (r3v174 int)
  (r3v184 int)
 binds: [B:615:0x0fa2, B:612:0x0f83, B:609:0x0f68, B:606:0x0f4e, B:603:0x0f34, B:599:0x0f17, B:592:0x0ef4, B:578:0x0eb7, B:570:0x0e61, B:552:0x0deb, B:542:0x0d8e] A[DONT_GENERATE, DONT_INLINE]
  0x0fba: PHI (r5v152 byte[]) = 
  (r5v125 byte[])
  (r5v126 byte[])
  (r5v127 byte[])
  (r5v128 byte[])
  (r5v129 byte[])
  (r5v131 byte[])
  (r5v132 byte[])
  (r5v133 byte[])
  (r5v138 byte[])
  (r5v146 byte[])
  (r5v153 byte[])
 binds: [B:615:0x0fa2, B:612:0x0f83, B:609:0x0f68, B:606:0x0f4e, B:603:0x0f34, B:599:0x0f17, B:592:0x0ef4, B:578:0x0eb7, B:570:0x0e61, B:552:0x0deb, B:542:0x0d8e] A[DONT_GENERATE, DONT_INLINE]
  0x0fba: PHI (r8v120 int) = 
  (r8v97 int)
  (r8v98 int)
  (r8v99 int)
  (r8v100 int)
  (r8v101 int)
  (r8v103 int)
  (r8v104 int)
  (r8v105 int)
  (r8v109 int)
  (r8v113 int)
  (r8v121 int)
 binds: [B:615:0x0fa2, B:612:0x0f83, B:609:0x0f68, B:606:0x0f4e, B:603:0x0f34, B:599:0x0f17, B:592:0x0ef4, B:578:0x0eb7, B:570:0x0e61, B:552:0x0deb, B:542:0x0d8e] A[DONT_GENERATE, DONT_INLINE]
  0x0fba: PHI (r15v116 com.google.android.gms.internal.measurement.x2) = 
  (r15v92 com.google.android.gms.internal.measurement.x2)
  (r15v93 com.google.android.gms.internal.measurement.x2)
  (r15v94 com.google.android.gms.internal.measurement.x2)
  (r15v95 com.google.android.gms.internal.measurement.x2)
  (r15v96 com.google.android.gms.internal.measurement.x2)
  (r15v98 com.google.android.gms.internal.measurement.x2)
  (r15v99 com.google.android.gms.internal.measurement.x2)
  (r15v100 com.google.android.gms.internal.measurement.x2)
  (r15v103 com.google.android.gms.internal.measurement.x2)
  (r15v112 com.google.android.gms.internal.measurement.x2)
  (r15v117 com.google.android.gms.internal.measurement.x2)
 binds: [B:615:0x0fa2, B:612:0x0f83, B:609:0x0f68, B:606:0x0f4e, B:603:0x0f34, B:599:0x0f17, B:592:0x0ef4, B:578:0x0eb7, B:570:0x0e61, B:552:0x0deb, B:542:0x0d8e] A[DONT_GENERATE, DONT_INLINE]
  0x0fba: PHI (r30v47 int) = 
  (r30v39 int)
  (r30v39 int)
  (r30v39 int)
  (r30v39 int)
  (r30v39 int)
  (r30v39 int)
  (r30v39 int)
  (r30v39 int)
  (r30v41 int)
  (r30v43 int)
  (r30v39 int)
 binds: [B:615:0x0fa2, B:612:0x0f83, B:609:0x0f68, B:606:0x0f4e, B:603:0x0f34, B:599:0x0f17, B:592:0x0ef4, B:578:0x0eb7, B:570:0x0e61, B:552:0x0deb, B:542:0x0d8e] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:670:0x0353 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:722:0x0cea A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:723:0x0fbd A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:754:0x0d02 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:759:0x0fd6 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:91:0x02ab  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int s(java.lang.Object r37, byte[] r38, int r39, int r40, int r41, com.google.android.gms.internal.ads.C2776wA r42) throws com.google.android.gms.internal.measurement.zzmm {
        /*
            Method dump skipped, instructions count: 4388
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.measurement.C3035o2.s(java.lang.Object, byte[], int, int, int, com.google.android.gms.internal.ads.wA):int");
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

    public final Z1 z(int i) {
        int i2 = i / 3;
        return (Z1) this.b[i2 + i2 + 1];
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3069v2
    public final W1 zze() {
        return (W1) ((W1) this.e).m(4);
    }
}
