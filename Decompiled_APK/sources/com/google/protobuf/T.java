package com.google.protobuf;

import androidx.core.view.AbstractC1047f0;
import com.appsflyer.attribution.RequestError;
import com.comscore.streaming.EventType;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import sun.misc.Unsafe;

/* loaded from: classes2.dex */
public final class T implements InterfaceC4009c0 {
    public static final int[] n = new int[0];
    public static final Unsafe o = t0.j();
    public final int[] a;
    public final Object[] b;
    public final int c;
    public final int d;
    public final AbstractC4004a e;
    public final boolean f;
    public final int[] g;
    public final int h;
    public final int i;
    public final V j;
    public final I k;
    public final j0 l;
    public final O m;

    public T(int[] iArr, Object[] objArr, int i, int i2, AbstractC4004a abstractC4004a, int[] iArr2, int i3, int i4, V v, I i5, j0 j0Var, C4021o c4021o, O o2) {
        this.a = iArr;
        this.b = objArr;
        this.c = i;
        this.d = i2;
        this.f = abstractC4004a instanceof AbstractC4027v;
        this.g = iArr2;
        this.h = i3;
        this.i = i4;
        this.j = v;
        this.k = i5;
        this.l = j0Var;
        this.e = abstractC4004a;
        this.m = o2;
    }

    public static long A(int i) {
        return i & 1048575;
    }

    public static int B(long j, Object obj) {
        return ((Integer) t0.c.i(j, obj)).intValue();
    }

    public static long C(long j, Object obj) {
        return ((Long) t0.c.i(j, obj)).longValue();
    }

    public static Field I(Class cls, String str) {
        try {
            return cls.getDeclaredField(str);
        } catch (NoSuchFieldException unused) {
            Field[] declaredFields = cls.getDeclaredFields();
            for (Field field : declaredFields) {
                if (str.equals(field.getName())) {
                    return field;
                }
            }
            StringBuilder sbY = android.support.v4.media.session.a.y("Field ", str, " for ");
            sbY.append(cls.getName());
            sbY.append(" not found. Known fields are ");
            sbY.append(Arrays.toString(declaredFields));
            throw new RuntimeException(sbY.toString());
        }
    }

    public static int N(int i) {
        return (i & 267386880) >>> 20;
    }

    public static boolean q(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj instanceof AbstractC4027v) {
            return ((AbstractC4027v) obj).p();
        }
        return true;
    }

    public static T y(C4007b0 c4007b0, V v, I i, j0 j0Var, C4021o c4021o, O o2) {
        if (c4007b0 instanceof C4007b0) {
            return z(c4007b0, v, i, j0Var, c4021o, o2);
        }
        c4007b0.getClass();
        throw new ClassCastException();
    }

    /* JADX WARN: Removed duplicated region for block: B:122:0x0267  */
    /* JADX WARN: Removed duplicated region for block: B:124:0x026e  */
    /* JADX WARN: Removed duplicated region for block: B:127:0x0284  */
    /* JADX WARN: Removed duplicated region for block: B:128:0x0287  */
    /* JADX WARN: Removed duplicated region for block: B:181:0x0384  */
    /* JADX WARN: Removed duplicated region for block: B:187:0x03a0  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.google.protobuf.T z(com.google.protobuf.C4007b0 r34, com.google.protobuf.V r35, com.google.protobuf.I r36, com.google.protobuf.j0 r37, com.google.protobuf.C4021o r38, com.google.protobuf.O r39) {
        /*
            Method dump skipped, instructions count: 1023
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.protobuf.T.z(com.google.protobuf.b0, com.google.protobuf.V, com.google.protobuf.I, com.google.protobuf.j0, com.google.protobuf.o, com.google.protobuf.O):com.google.protobuf.T");
    }

    public final int D(int i) {
        if (i >= this.c && i <= this.d) {
            int[] iArr = this.a;
            int length = (iArr.length / 3) - 1;
            int i2 = 0;
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
        }
        return -1;
    }

    public final void E(Object obj, long j, C4015i c4015i, InterfaceC4009c0 interfaceC4009c0, C4020n c4020n) throws InvalidProtocolBufferException.InvalidWireTypeException {
        int iB;
        List listC = this.k.c(j, obj);
        int i = c4015i.b;
        if ((i & 7) != 3) {
            throw InvalidProtocolBufferException.b();
        }
        do {
            AbstractC4027v abstractC4027vD = interfaceC4009c0.d();
            c4015i.b(abstractC4027vD, interfaceC4009c0, c4020n);
            interfaceC4009c0.b(abstractC4027vD);
            listC.add(abstractC4027vD);
            AbstractC1047f0 abstractC1047f0 = c4015i.a;
            if (abstractC1047f0.c() || c4015i.d != 0) {
                return;
            } else {
                iB = abstractC1047f0.B();
            }
        } while (iB == i);
        c4015i.d = iB;
    }

    public final void F(Object obj, int i, C4015i c4015i, InterfaceC4009c0 interfaceC4009c0, C4020n c4020n) throws InvalidProtocolBufferException {
        int iB;
        List listC = this.k.c(i & 1048575, obj);
        int i2 = c4015i.b;
        if ((i2 & 7) != 2) {
            throw InvalidProtocolBufferException.b();
        }
        do {
            AbstractC4027v abstractC4027vD = interfaceC4009c0.d();
            c4015i.c(abstractC4027vD, interfaceC4009c0, c4020n);
            interfaceC4009c0.b(abstractC4027vD);
            listC.add(abstractC4027vD);
            AbstractC1047f0 abstractC1047f0 = c4015i.a;
            if (abstractC1047f0.c() || c4015i.d != 0) {
                return;
            } else {
                iB = abstractC1047f0.B();
            }
        } while (iB == i2);
        c4015i.d = iB;
    }

    public final void G(Object obj, int i, C4015i c4015i) throws InvalidProtocolBufferException.InvalidWireTypeException {
        if ((536870912 & i) != 0) {
            c4015i.w(2);
            t0.p(i & 1048575, obj, c4015i.a.A());
        } else if (!this.f) {
            t0.p(i & 1048575, obj, c4015i.e());
        } else {
            c4015i.w(2);
            t0.p(i & 1048575, obj, c4015i.a.z());
        }
    }

    public final void H(Object obj, int i, C4015i c4015i) throws InvalidProtocolBufferException.InvalidWireTypeException {
        boolean z = (536870912 & i) != 0;
        I i2 = this.k;
        if (z) {
            c4015i.s(i2.c(i & 1048575, obj), true);
        } else {
            c4015i.s(i2.c(i & 1048575, obj), false);
        }
    }

    public final void J(int i, Object obj) {
        int i2 = this.a[i + 2];
        long j = 1048575 & i2;
        if (j == 1048575) {
            return;
        }
        t0.n(j, obj, (1 << (i2 >>> 20)) | t0.c.g(j, obj));
    }

    public final void K(int i, int i2, Object obj) {
        t0.n(this.a[i2 + 2] & 1048575, obj, i);
    }

    public final void L(Object obj, int i, AbstractC4004a abstractC4004a) {
        o.putObject(obj, O(i) & 1048575, abstractC4004a);
        J(i, obj);
    }

    public final void M(Object obj, int i, int i2, AbstractC4004a abstractC4004a) {
        o.putObject(obj, O(i2) & 1048575, abstractC4004a);
        K(i, i2, obj);
    }

    public final int O(int i) {
        return this.a[i + 1];
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    public final void P(Object obj, K k) {
        int i;
        int i2;
        int i3;
        char c;
        int i4;
        int i5;
        int i6;
        boolean z;
        T t = this;
        int[] iArr = t.a;
        int length = iArr.length;
        Unsafe unsafe = o;
        int i7 = 1048575;
        int i8 = 1048575;
        int i9 = 0;
        int i10 = 0;
        while (i9 < length) {
            int iO = t.O(i9);
            int i11 = iArr[i9];
            int iN = N(iO);
            if (iN <= 17) {
                int i12 = iArr[i9 + 2];
                i = 1;
                int i13 = i12 & i7;
                if (i13 != i8) {
                    i10 = i13 == i7 ? 0 : unsafe.getInt(obj, i13);
                    i8 = i13;
                }
                i2 = iO;
                i3 = 1 << (i12 >>> 20);
            } else {
                i = 1;
                i2 = iO;
                i3 = 0;
            }
            long j = i2 & i7;
            switch (iN) {
                case 0:
                    c = 2;
                    if (t.p(obj, i9, i8, i10, i3)) {
                        double dE = t0.c.e(j, obj);
                        AbstractC4018l abstractC4018l = (AbstractC4018l) k.a;
                        abstractC4018l.getClass();
                        abstractC4018l.u(i11, Double.doubleToRawLongBits(dE));
                        break;
                    } else {
                        break;
                    }
                case 1:
                    c = 2;
                    if (t.p(obj, i9, i8, i10, i3)) {
                        float f = t0.c.f(j, obj);
                        AbstractC4018l abstractC4018l2 = (AbstractC4018l) k.a;
                        abstractC4018l2.getClass();
                        abstractC4018l2.s(i11, Float.floatToRawIntBits(f));
                    }
                    t = this;
                    break;
                case 2:
                    c = 2;
                    if (t.p(obj, i9, i8, i10, i3)) {
                        ((AbstractC4018l) k.a).F(i11, unsafe.getLong(obj, j));
                    }
                    t = this;
                    break;
                case 3:
                    c = 2;
                    if (t.p(obj, i9, i8, i10, i3)) {
                        ((AbstractC4018l) k.a).F(i11, unsafe.getLong(obj, j));
                    }
                    t = this;
                    break;
                case 4:
                    c = 2;
                    if (t.p(obj, i9, i8, i10, i3)) {
                        ((AbstractC4018l) k.a).w(i11, unsafe.getInt(obj, j));
                    }
                    t = this;
                    break;
                case 5:
                    c = 2;
                    if (t.p(obj, i9, i8, i10, i3)) {
                        ((AbstractC4018l) k.a).u(i11, unsafe.getLong(obj, j));
                    }
                    t = this;
                    break;
                case 6:
                    c = 2;
                    if (t.p(obj, i9, i8, i10, i3)) {
                        ((AbstractC4018l) k.a).s(i11, unsafe.getInt(obj, j));
                    }
                    t = this;
                    break;
                case 7:
                    c = 2;
                    if (t.p(obj, i9, i8, i10, i3)) {
                        ((AbstractC4018l) k.a).o(i11, t0.c.c(j, obj));
                    }
                    t = this;
                    break;
                case 8:
                    c = 2;
                    if (t.p(obj, i9, i8, i10, i3)) {
                        Object object = unsafe.getObject(obj, j);
                        if (object instanceof String) {
                            ((AbstractC4018l) k.a).A(i11, (String) object);
                        } else {
                            ((AbstractC4018l) k.a).q(i11, (C4012f) object);
                        }
                    }
                    t = this;
                    break;
                case 9:
                    c = 2;
                    if (t.p(obj, i9, i8, i10, i3)) {
                        ((AbstractC4018l) k.a).y(i11, (AbstractC4004a) unsafe.getObject(obj, j), t.n(i9));
                        break;
                    } else {
                        break;
                    }
                case 10:
                    c = 2;
                    if (t.p(obj, i9, i8, i10, i3)) {
                        ((AbstractC4018l) k.a).q(i11, (C4012f) unsafe.getObject(obj, j));
                    }
                    t = this;
                    break;
                case 11:
                    c = 2;
                    if (t.p(obj, i9, i8, i10, i3)) {
                        ((AbstractC4018l) k.a).D(i11, unsafe.getInt(obj, j));
                    }
                    t = this;
                    break;
                case 12:
                    c = 2;
                    if (t.p(obj, i9, i8, i10, i3)) {
                        ((AbstractC4018l) k.a).w(i11, unsafe.getInt(obj, j));
                    }
                    t = this;
                    break;
                case 13:
                    c = 2;
                    if (t.p(obj, i9, i8, i10, i3)) {
                        ((AbstractC4018l) k.a).s(i11, unsafe.getInt(obj, j));
                    }
                    t = this;
                    break;
                case 14:
                    c = 2;
                    if (t.p(obj, i9, i8, i10, i3)) {
                        ((AbstractC4018l) k.a).u(i11, unsafe.getLong(obj, j));
                    }
                    t = this;
                    break;
                case 15:
                    c = 2;
                    if (t.p(obj, i9, i8, i10, i3)) {
                        int i14 = unsafe.getInt(obj, j);
                        ((AbstractC4018l) k.a).D(i11, (i14 >> 31) ^ (i14 << 1));
                    }
                    t = this;
                    break;
                case 16:
                    c = 2;
                    if (t.p(obj, i9, i8, i10, i3)) {
                        long j2 = unsafe.getLong(obj, j);
                        ((AbstractC4018l) k.a).F(i11, (j2 >> 63) ^ (j2 << 1));
                    }
                    t = this;
                    break;
                case 17:
                    c = 2;
                    if (t.p(obj, i9, i8, i10, i3)) {
                        k.a(i11, unsafe.getObject(obj, j), t.n(i9));
                    }
                    break;
                case 18:
                    i4 = i8;
                    c = 2;
                    d0.n(iArr[i9], (List) unsafe.getObject(obj, j), k, false);
                    i8 = i4;
                    break;
                case 19:
                    i4 = i8;
                    c = 2;
                    d0.r(iArr[i9], (List) unsafe.getObject(obj, j), k, false);
                    i8 = i4;
                    break;
                case 20:
                    i4 = i8;
                    c = 2;
                    d0.t(iArr[i9], (List) unsafe.getObject(obj, j), k, false);
                    i8 = i4;
                    break;
                case 21:
                    i4 = i8;
                    c = 2;
                    d0.z(iArr[i9], (List) unsafe.getObject(obj, j), k, false);
                    i8 = i4;
                    break;
                case EventType.WINDOW_STATE /* 22 */:
                    i4 = i8;
                    c = 2;
                    d0.s(iArr[i9], (List) unsafe.getObject(obj, j), k, false);
                    i8 = i4;
                    break;
                case EventType.AUDIO /* 23 */:
                    i4 = i8;
                    c = 2;
                    d0.q(iArr[i9], (List) unsafe.getObject(obj, j), k, false);
                    i8 = i4;
                    break;
                case EventType.VIDEO /* 24 */:
                    i4 = i8;
                    c = 2;
                    d0.p(iArr[i9], (List) unsafe.getObject(obj, j), k, false);
                    i8 = i4;
                    break;
                case EventType.SUBS /* 25 */:
                    i4 = i8;
                    c = 2;
                    d0.m(iArr[i9], (List) unsafe.getObject(obj, j), k, false);
                    i8 = i4;
                    break;
                case EventType.CDN /* 26 */:
                    i5 = i8;
                    c = 2;
                    int i15 = iArr[i9];
                    List list = (List) unsafe.getObject(obj, j);
                    Class cls = d0.a;
                    if (list != null && !list.isEmpty()) {
                        k.getClass();
                        boolean z2 = list instanceof F;
                        AbstractC4018l abstractC4018l3 = (AbstractC4018l) k.a;
                        if (z2) {
                            F f2 = (F) list;
                            for (int i16 = 0; i16 < list.size(); i16++) {
                                Object objP = f2.P(i16);
                                if (objP instanceof String) {
                                    abstractC4018l3.A(i15, (String) objP);
                                } else {
                                    abstractC4018l3.q(i15, (C4012f) objP);
                                }
                            }
                        } else {
                            for (int i17 = 0; i17 < list.size(); i17++) {
                                abstractC4018l3.A(i15, (String) list.get(i17));
                            }
                        }
                    }
                    i8 = i5;
                    break;
                case 27:
                    i5 = i8;
                    c = 2;
                    int i18 = iArr[i9];
                    List list2 = (List) unsafe.getObject(obj, j);
                    InterfaceC4009c0 interfaceC4009c0N = t.n(i9);
                    Class cls2 = d0.a;
                    if (list2 != null && !list2.isEmpty()) {
                        k.getClass();
                        for (int i19 = 0; i19 < list2.size(); i19++) {
                            ((AbstractC4018l) k.a).y(i18, (AbstractC4004a) list2.get(i19), interfaceC4009c0N);
                        }
                    }
                    i8 = i5;
                    break;
                case 28:
                    i5 = i8;
                    c = 2;
                    int i20 = iArr[i9];
                    List list3 = (List) unsafe.getObject(obj, j);
                    Class cls3 = d0.a;
                    if (list3 != null && !list3.isEmpty()) {
                        k.getClass();
                        for (int i21 = 0; i21 < list3.size(); i21++) {
                            ((AbstractC4018l) k.a).q(i20, (C4012f) list3.get(i21));
                        }
                    }
                    i8 = i5;
                    break;
                case 29:
                    i4 = i8;
                    c = 2;
                    d0.y(iArr[i9], (List) unsafe.getObject(obj, j), k, false);
                    i8 = i4;
                    break;
                case 30:
                    i4 = i8;
                    c = 2;
                    d0.o(iArr[i9], (List) unsafe.getObject(obj, j), k, false);
                    i8 = i4;
                    break;
                case 31:
                    i4 = i8;
                    c = 2;
                    d0.u(iArr[i9], (List) unsafe.getObject(obj, j), k, false);
                    i8 = i4;
                    break;
                case 32:
                    i4 = i8;
                    c = 2;
                    d0.v(iArr[i9], (List) unsafe.getObject(obj, j), k, false);
                    i8 = i4;
                    break;
                case 33:
                    i4 = i8;
                    c = 2;
                    d0.w(iArr[i9], (List) unsafe.getObject(obj, j), k, false);
                    i8 = i4;
                    break;
                case 34:
                    i4 = i8;
                    c = 2;
                    d0.x(iArr[i9], (List) unsafe.getObject(obj, j), k, false);
                    i8 = i4;
                    break;
                case 35:
                    i6 = i8;
                    z = i == true ? 1 : 0;
                    c = 2;
                    d0.n(iArr[i9], (List) unsafe.getObject(obj, j), k, z);
                    i8 = i6;
                    break;
                case 36:
                    i6 = i8;
                    z = i == true ? 1 : 0;
                    c = 2;
                    d0.r(iArr[i9], (List) unsafe.getObject(obj, j), k, z);
                    i8 = i6;
                    break;
                case 37:
                    i6 = i8;
                    z = i == true ? 1 : 0;
                    c = 2;
                    d0.t(iArr[i9], (List) unsafe.getObject(obj, j), k, z);
                    i8 = i6;
                    break;
                case 38:
                    i6 = i8;
                    z = i == true ? 1 : 0;
                    c = 2;
                    d0.z(iArr[i9], (List) unsafe.getObject(obj, j), k, z);
                    i8 = i6;
                    break;
                case 39:
                    i6 = i8;
                    z = i == true ? 1 : 0;
                    c = 2;
                    d0.s(iArr[i9], (List) unsafe.getObject(obj, j), k, z);
                    i8 = i6;
                    break;
                case RequestError.NETWORK_FAILURE /* 40 */:
                    i6 = i8;
                    z = i == true ? 1 : 0;
                    c = 2;
                    d0.q(iArr[i9], (List) unsafe.getObject(obj, j), k, z);
                    i8 = i6;
                    break;
                case RequestError.NO_DEV_KEY /* 41 */:
                    i6 = i8;
                    z = i == true ? 1 : 0;
                    c = 2;
                    d0.p(iArr[i9], (List) unsafe.getObject(obj, j), k, z);
                    i8 = i6;
                    break;
                case 42:
                    i6 = i8;
                    z = i == true ? 1 : 0;
                    c = 2;
                    d0.m(iArr[i9], (List) unsafe.getObject(obj, j), k, z);
                    i8 = i6;
                    break;
                case 43:
                    i6 = i8;
                    z = i == true ? 1 : 0;
                    c = 2;
                    d0.y(iArr[i9], (List) unsafe.getObject(obj, j), k, z);
                    i8 = i6;
                    break;
                case 44:
                    i6 = i8;
                    z = i == true ? 1 : 0;
                    c = 2;
                    d0.o(iArr[i9], (List) unsafe.getObject(obj, j), k, z);
                    i8 = i6;
                    break;
                case 45:
                    i6 = i8;
                    z = i == true ? 1 : 0;
                    c = 2;
                    d0.u(iArr[i9], (List) unsafe.getObject(obj, j), k, z);
                    i8 = i6;
                    break;
                case 46:
                    i6 = i8;
                    z = i == true ? 1 : 0;
                    c = 2;
                    d0.v(iArr[i9], (List) unsafe.getObject(obj, j), k, z);
                    i8 = i6;
                    break;
                case 47:
                    i6 = i8;
                    z = i == true ? 1 : 0;
                    c = 2;
                    d0.w(iArr[i9], (List) unsafe.getObject(obj, j), k, z);
                    i8 = i6;
                    break;
                case 48:
                    i6 = i8;
                    z = i == true ? 1 : 0;
                    c = 2;
                    d0.x(iArr[i9], (List) unsafe.getObject(obj, j), k, z);
                    i8 = i6;
                    break;
                case 49:
                    i6 = i8;
                    c = 2;
                    int i22 = iArr[i9];
                    List list4 = (List) unsafe.getObject(obj, j);
                    InterfaceC4009c0 interfaceC4009c0N2 = t.n(i9);
                    Class cls4 = d0.a;
                    if (list4 != null && !list4.isEmpty()) {
                        k.getClass();
                        for (int i23 = 0; i23 < list4.size(); i23++) {
                            k.a(i22, list4.get(i23), interfaceC4009c0N2);
                        }
                    }
                    z = true;
                    i8 = i6;
                    break;
                case RequestError.RESPONSE_CODE_FAILURE /* 50 */:
                    Object object2 = unsafe.getObject(obj, j);
                    if (object2 != null) {
                        Object objM = t.m(i9);
                        t.m.getClass();
                        L l = ((M) objM).a;
                        AbstractC4018l abstractC4018l4 = (AbstractC4018l) k.a;
                        abstractC4018l4.getClass();
                        for (Map.Entry entry : ((N) object2).entrySet()) {
                            abstractC4018l4.C(i11, 2);
                            abstractC4018l4.E(M.a(l, entry.getKey(), entry.getValue()));
                            Object key = entry.getKey();
                            Object value = entry.getValue();
                            C4023q.b(abstractC4018l4, l.a, i, key);
                            C4023q.b(abstractC4018l4, l.b, 2, value);
                            i8 = i8;
                            i = 1;
                        }
                    }
                    i5 = i8;
                    c = 2;
                    i8 = i5;
                    break;
                case 51:
                    if (t.r(i11, i9, obj)) {
                        double dDoubleValue = ((Double) t0.c.i(j, obj)).doubleValue();
                        AbstractC4018l abstractC4018l5 = (AbstractC4018l) k.a;
                        abstractC4018l5.getClass();
                        abstractC4018l5.u(i11, Double.doubleToRawLongBits(dDoubleValue));
                    }
                    c = 2;
                    break;
                case 52:
                    if (t.r(i11, i9, obj)) {
                        float fFloatValue = ((Float) t0.c.i(j, obj)).floatValue();
                        AbstractC4018l abstractC4018l6 = (AbstractC4018l) k.a;
                        abstractC4018l6.getClass();
                        abstractC4018l6.s(i11, Float.floatToRawIntBits(fFloatValue));
                    }
                    c = 2;
                    break;
                case 53:
                    if (t.r(i11, i9, obj)) {
                        ((AbstractC4018l) k.a).F(i11, C(j, obj));
                    }
                    c = 2;
                    break;
                case 54:
                    if (t.r(i11, i9, obj)) {
                        ((AbstractC4018l) k.a).F(i11, C(j, obj));
                    }
                    c = 2;
                    break;
                case 55:
                    if (t.r(i11, i9, obj)) {
                        ((AbstractC4018l) k.a).w(i11, B(j, obj));
                    }
                    c = 2;
                    break;
                case 56:
                    if (t.r(i11, i9, obj)) {
                        ((AbstractC4018l) k.a).u(i11, C(j, obj));
                    }
                    c = 2;
                    break;
                case 57:
                    if (t.r(i11, i9, obj)) {
                        ((AbstractC4018l) k.a).s(i11, B(j, obj));
                    }
                    c = 2;
                    break;
                case 58:
                    if (t.r(i11, i9, obj)) {
                        ((AbstractC4018l) k.a).o(i11, ((Boolean) t0.c.i(j, obj)).booleanValue());
                    }
                    c = 2;
                    break;
                case 59:
                    if (t.r(i11, i9, obj)) {
                        Object object3 = unsafe.getObject(obj, j);
                        if (object3 instanceof String) {
                            ((AbstractC4018l) k.a).A(i11, (String) object3);
                        } else {
                            ((AbstractC4018l) k.a).q(i11, (C4012f) object3);
                        }
                    }
                    c = 2;
                    break;
                case 60:
                    if (t.r(i11, i9, obj)) {
                        ((AbstractC4018l) k.a).y(i11, (AbstractC4004a) unsafe.getObject(obj, j), t.n(i9));
                    }
                    c = 2;
                    break;
                case 61:
                    if (t.r(i11, i9, obj)) {
                        ((AbstractC4018l) k.a).q(i11, (C4012f) unsafe.getObject(obj, j));
                    }
                    c = 2;
                    break;
                case 62:
                    if (t.r(i11, i9, obj)) {
                        ((AbstractC4018l) k.a).D(i11, B(j, obj));
                    }
                    c = 2;
                    break;
                case 63:
                    if (t.r(i11, i9, obj)) {
                        ((AbstractC4018l) k.a).w(i11, B(j, obj));
                    }
                    c = 2;
                    break;
                case 64:
                    if (t.r(i11, i9, obj)) {
                        ((AbstractC4018l) k.a).s(i11, B(j, obj));
                    }
                    c = 2;
                    break;
                case 65:
                    if (t.r(i11, i9, obj)) {
                        ((AbstractC4018l) k.a).u(i11, C(j, obj));
                    }
                    c = 2;
                    break;
                case 66:
                    if (t.r(i11, i9, obj)) {
                        int iB = B(j, obj);
                        ((AbstractC4018l) k.a).D(i11, (iB >> 31) ^ (iB << 1));
                    }
                    c = 2;
                    break;
                case 67:
                    if (t.r(i11, i9, obj)) {
                        long jC = C(j, obj);
                        ((AbstractC4018l) k.a).F(i11, (jC << (i == true ? 1L : 0L)) ^ (jC >> 63));
                    }
                    c = 2;
                    break;
                case 68:
                    if (t.r(i11, i9, obj)) {
                        k.a(i11, unsafe.getObject(obj, j), t.n(i9));
                    }
                    c = 2;
                    break;
                default:
                    c = 2;
                    break;
            }
            i9 += 3;
            i7 = 1048575;
        }
        ((l0) t.l).getClass();
        ((AbstractC4027v) obj).unknownFields.d(k);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:11:0x0025  */
    @Override // com.google.protobuf.InterfaceC4009c0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(java.lang.Object r11, java.lang.Object r12) {
        /*
            Method dump skipped, instructions count: 606
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.protobuf.T.a(java.lang.Object, java.lang.Object):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x0070  */
    @Override // com.google.protobuf.InterfaceC4009c0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(java.lang.Object r10) {
        /*
            r9 = this;
            boolean r0 = q(r10)
            if (r0 != 0) goto L8
            goto L97
        L8:
            boolean r0 = r10 instanceof com.google.protobuf.AbstractC4027v
            r1 = 0
            if (r0 == 0) goto L1b
            r0 = r10
            com.google.protobuf.v r0 = (com.google.protobuf.AbstractC4027v) r0
            r2 = 2147483647(0x7fffffff, float:NaN)
            r0.v(r2)
            r0.memoizedHashCode = r1
            r0.q()
        L1b:
            int[] r0 = r9.a
            int r2 = r0.length
            r3 = r1
        L1f:
            if (r3 >= r2) goto L86
            int r4 = r9.O(r3)
            r5 = 1048575(0xfffff, float:1.469367E-39)
            r5 = r5 & r4
            long r5 = (long) r5
            int r4 = N(r4)
            r7 = 9
            if (r4 == r7) goto L70
            r7 = 60
            if (r4 == r7) goto L5a
            r7 = 68
            if (r4 == r7) goto L5a
            switch(r4) {
                case 17: goto L70;
                case 18: goto L54;
                case 19: goto L54;
                case 20: goto L54;
                case 21: goto L54;
                case 22: goto L54;
                case 23: goto L54;
                case 24: goto L54;
                case 25: goto L54;
                case 26: goto L54;
                case 27: goto L54;
                case 28: goto L54;
                case 29: goto L54;
                case 30: goto L54;
                case 31: goto L54;
                case 32: goto L54;
                case 33: goto L54;
                case 34: goto L54;
                case 35: goto L54;
                case 36: goto L54;
                case 37: goto L54;
                case 38: goto L54;
                case 39: goto L54;
                case 40: goto L54;
                case 41: goto L54;
                case 42: goto L54;
                case 43: goto L54;
                case 44: goto L54;
                case 45: goto L54;
                case 46: goto L54;
                case 47: goto L54;
                case 48: goto L54;
                case 49: goto L54;
                case 50: goto L3e;
                default: goto L3d;
            }
        L3d:
            goto L83
        L3e:
            sun.misc.Unsafe r4 = com.google.protobuf.T.o
            java.lang.Object r7 = r4.getObject(r10, r5)
            if (r7 == 0) goto L83
            com.google.protobuf.O r8 = r9.m
            r8.getClass()
            r8 = r7
            com.google.protobuf.N r8 = (com.google.protobuf.N) r8
            r8.a = r1
            r4.putObject(r10, r5, r7)
            goto L83
        L54:
            com.google.protobuf.I r4 = r9.k
            r4.a(r5, r10)
            goto L83
        L5a:
            r4 = r0[r3]
            boolean r4 = r9.r(r4, r3, r10)
            if (r4 == 0) goto L83
            com.google.protobuf.c0 r4 = r9.n(r3)
            sun.misc.Unsafe r7 = com.google.protobuf.T.o
            java.lang.Object r5 = r7.getObject(r10, r5)
            r4.b(r5)
            goto L83
        L70:
            boolean r4 = r9.o(r3, r10)
            if (r4 == 0) goto L83
            com.google.protobuf.c0 r4 = r9.n(r3)
            sun.misc.Unsafe r7 = com.google.protobuf.T.o
            java.lang.Object r5 = r7.getObject(r10, r5)
            r4.b(r5)
        L83:
            int r3 = r3 + 3
            goto L1f
        L86:
            com.google.protobuf.j0 r0 = r9.l
            com.google.protobuf.l0 r0 = (com.google.protobuf.l0) r0
            r0.getClass()
            com.google.protobuf.v r10 = (com.google.protobuf.AbstractC4027v) r10
            com.google.protobuf.k0 r10 = r10.unknownFields
            boolean r0 = r10.e
            if (r0 == 0) goto L97
            r10.e = r1
        L97:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.protobuf.T.b(java.lang.Object):void");
    }

    @Override // com.google.protobuf.InterfaceC4009c0
    public final boolean c(Object obj) {
        int i;
        int i2;
        int i3;
        int i4 = 1048575;
        int i5 = 0;
        int i6 = 0;
        while (i6 < this.h) {
            int i7 = this.g[i6];
            int[] iArr = this.a;
            int i8 = iArr[i7];
            int iO = O(i7);
            int i9 = iArr[i7 + 2];
            int i10 = i9 & 1048575;
            int i11 = 1 << (i9 >>> 20);
            if (i10 != i4) {
                if (i10 != 1048575) {
                    i5 = o.getInt(obj, i10);
                }
                i2 = i7;
                i3 = i5;
                i = i10;
            } else {
                int i12 = i5;
                i = i4;
                i2 = i7;
                i3 = i12;
            }
            if ((268435456 & iO) == 0 || p(obj, i2, i, i3, i11)) {
                int iN = N(iO);
                if (iN == 9 || iN == 17) {
                    if (p(obj, i2, i, i3, i11)) {
                        if (!n(i2).c(t0.c.i(iO & 1048575, obj))) {
                        }
                    } else {
                        continue;
                    }
                    i6++;
                    i4 = i;
                    i5 = i3;
                } else {
                    if (iN != 27) {
                        if (iN == 60 || iN == 68) {
                            if (r(i8, i2, obj)) {
                                if (!n(i2).c(t0.c.i(iO & 1048575, obj))) {
                                }
                            } else {
                                continue;
                            }
                            i6++;
                            i4 = i;
                            i5 = i3;
                        } else if (iN != 49) {
                            if (iN != 50) {
                                continue;
                            } else {
                                Object objI = t0.c.i(iO & 1048575, obj);
                                this.m.getClass();
                                N n2 = (N) objI;
                                if (!n2.isEmpty() && ((M) m(i2)).a.b.a == C0.MESSAGE) {
                                    InterfaceC4009c0 interfaceC4009c0A = null;
                                    for (Object obj2 : n2.values()) {
                                        if (interfaceC4009c0A == null) {
                                            interfaceC4009c0A = Z.c.a(obj2.getClass());
                                        }
                                        if (!interfaceC4009c0A.c(obj2)) {
                                        }
                                    }
                                }
                            }
                            i6++;
                            i4 = i;
                            i5 = i3;
                        }
                    }
                    List list = (List) t0.c.i(iO & 1048575, obj);
                    if (list.isEmpty()) {
                        continue;
                    } else {
                        InterfaceC4009c0 interfaceC4009c0N = n(i2);
                        for (int i13 = 0; i13 < list.size(); i13++) {
                            if (interfaceC4009c0N.c(list.get(i13))) {
                            }
                        }
                    }
                    i6++;
                    i4 = i;
                    i5 = i3;
                }
            }
            return false;
        }
        return true;
    }

    @Override // com.google.protobuf.InterfaceC4009c0
    public final AbstractC4027v d() {
        this.j.getClass();
        return ((AbstractC4027v) this.e).s();
    }

    @Override // com.google.protobuf.InterfaceC4009c0
    public final void e(Object obj, K k) {
        k.getClass();
        P(obj, k);
    }

    @Override // com.google.protobuf.InterfaceC4009c0
    public final void f(Object obj, C4015i c4015i, C4020n c4020n) {
        c4020n.getClass();
        if (!q(obj)) {
            throw new IllegalArgumentException(androidx.compose.ui.node.B.e(obj, "Mutating immutable message: "));
        }
        s(this.l, obj, c4015i, c4020n);
    }

    /* JADX WARN: Removed duplicated region for block: B:42:0x00e1 A[PHI: r3
  0x00e1: PHI (r3v32 int) = (r3v10 int), (r3v33 int) binds: [B:83:0x0216, B:41:0x00df] A[DONT_GENERATE, DONT_INLINE]] */
    @Override // com.google.protobuf.InterfaceC4009c0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int g(com.google.protobuf.AbstractC4027v r12) {
        /*
            Method dump skipped, instructions count: 796
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.protobuf.T.g(com.google.protobuf.v):int");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:146:0x03b3 A[PHI: r17
  0x03b3: PHI (r17v46 int) = 
  (r17v29 int)
  (r17v30 int)
  (r17v31 int)
  (r17v35 int)
  (r17v37 int)
  (r17v38 int)
  (r17v39 int)
  (r17v43 int)
  (r17v47 int)
 binds: [B:215:0x0561, B:211:0x0545, B:207:0x0529, B:179:0x0498, B:166:0x043a, B:162:0x0420, B:158:0x0406, B:151:0x03d0, B:145:0x03b1] A[DONT_GENERATE, DONT_INLINE]] */
    @Override // com.google.protobuf.InterfaceC4009c0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int h(com.google.protobuf.AbstractC4027v r19) {
        /*
            Method dump skipped, instructions count: 1992
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.protobuf.T.h(com.google.protobuf.v):int");
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x003d  */
    @Override // com.google.protobuf.InterfaceC4009c0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean i(com.google.protobuf.AbstractC4027v r12, com.google.protobuf.AbstractC4027v r13) {
        /*
            Method dump skipped, instructions count: 666
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.protobuf.T.i(com.google.protobuf.v, com.google.protobuf.v):boolean");
    }

    public final boolean j(AbstractC4027v abstractC4027v, AbstractC4027v abstractC4027v2, int i) {
        return o(i, abstractC4027v) == o(i, abstractC4027v2);
    }

    public final Object k(Object obj, int i, Object obj2, j0 j0Var, Object obj3) {
        InterfaceC4030y interfaceC4030yL;
        int i2 = this.a[i];
        Object objI = t0.c.i(O(i) & 1048575, obj);
        if (objI == null || (interfaceC4030yL = l(i)) == null) {
            return obj2;
        }
        this.m.getClass();
        L l = ((M) m(i)).a;
        Iterator it2 = ((N) objI).entrySet().iterator();
        while (it2.hasNext()) {
            Map.Entry entry = (Map.Entry) it2.next();
            if (!interfaceC4030yL.a(((Integer) entry.getValue()).intValue())) {
                if (obj2 == null) {
                    obj2 = j0Var.a(obj3);
                }
                int iA = M.a(l, entry.getKey(), entry.getValue());
                byte[] bArr = new byte[iA];
                C4016j c4016j = new C4016j(iA, bArr);
                try {
                    Object key = entry.getKey();
                    Object value = entry.getValue();
                    C4023q.b(c4016j, l.a, 1, key);
                    C4023q.b(c4016j, l.b, 2, value);
                    if (c4016j.H() != 0) {
                        throw new IllegalStateException("Did not write as much data as expected.");
                    }
                    C4012f c4012f = new C4012f(bArr);
                    ((l0) j0Var).getClass();
                    ((k0) obj2).c((i2 << 3) | 2, c4012f);
                    it2.remove();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        }
        return obj2;
    }

    public final InterfaceC4030y l(int i) {
        return (InterfaceC4030y) this.b[((i / 3) * 2) + 1];
    }

    public final Object m(int i) {
        return this.b[(i / 3) * 2];
    }

    public final InterfaceC4009c0 n(int i) {
        int i2 = (i / 3) * 2;
        Object[] objArr = this.b;
        InterfaceC4009c0 interfaceC4009c0 = (InterfaceC4009c0) objArr[i2];
        if (interfaceC4009c0 != null) {
            return interfaceC4009c0;
        }
        InterfaceC4009c0 interfaceC4009c0A = Z.c.a((Class) objArr[i2 + 1]);
        objArr[i2] = interfaceC4009c0A;
        return interfaceC4009c0A;
    }

    public final boolean o(int i, Object obj) {
        int i2 = this.a[i + 2];
        long j = i2 & 1048575;
        if (j == 1048575) {
            int iO = O(i);
            long j2 = iO & 1048575;
            switch (N(iO)) {
                case 0:
                    if (Double.doubleToRawLongBits(t0.c.e(j2, obj)) == 0) {
                        return false;
                    }
                    break;
                case 1:
                    if (Float.floatToRawIntBits(t0.c.f(j2, obj)) == 0) {
                        return false;
                    }
                    break;
                case 2:
                    if (t0.c.h(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 3:
                    if (t0.c.h(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 4:
                    if (t0.c.g(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 5:
                    if (t0.c.h(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 6:
                    if (t0.c.g(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 7:
                    return t0.c.c(j2, obj);
                case 8:
                    Object objI = t0.c.i(j2, obj);
                    if (objI instanceof String) {
                        return !((String) objI).isEmpty();
                    }
                    if (objI instanceof C4012f) {
                        return !C4012f.c.equals(objI);
                    }
                    throw new IllegalArgumentException();
                case 9:
                    if (t0.c.i(j2, obj) == null) {
                        return false;
                    }
                    break;
                case 10:
                    return !C4012f.c.equals(t0.c.i(j2, obj));
                case 11:
                    if (t0.c.g(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 12:
                    if (t0.c.g(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 13:
                    if (t0.c.g(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 14:
                    if (t0.c.h(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 15:
                    if (t0.c.g(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 16:
                    if (t0.c.h(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 17:
                    if (t0.c.i(j2, obj) == null) {
                        return false;
                    }
                    break;
                default:
                    throw new IllegalArgumentException();
            }
        } else if (((1 << (i2 >>> 20)) & t0.c.g(j, obj)) == 0) {
            return false;
        }
        return true;
    }

    public final boolean p(Object obj, int i, int i2, int i3, int i4) {
        return i2 == 1048575 ? o(i, obj) : (i3 & i4) != 0;
    }

    public final boolean r(int i, int i2, Object obj) {
        return t0.c.g((long) (this.a[i2 + 2] & 1048575), obj) == i;
    }

    /*  JADX ERROR: Type inference failed
        jadx.core.utils.exceptions.JadxOverflowException: Type inference error: updates count limit reached
        	at jadx.core.utils.ErrorsCounter.addError(ErrorsCounter.java:59)
        	at jadx.core.utils.ErrorsCounter.error(ErrorsCounter.java:31)
        	at jadx.core.dex.attributes.nodes.NotificationAttrNode.addError(NotificationAttrNode.java:19)
        	at jadx.core.dex.visitors.typeinference.TypeInferenceVisitor.visit(TypeInferenceVisitor.java:77)
        */
    public final void s(com.google.protobuf.j0 r19, java.lang.Object r20, com.google.protobuf.C4015i r21, com.google.protobuf.C4020n r22) {
        /*
            Method dump skipped, instructions count: 2332
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.protobuf.T.s(com.google.protobuf.j0, java.lang.Object, com.google.protobuf.i, com.google.protobuf.n):void");
    }

    /* JADX WARN: Code restructure failed: missing block: B:32:0x0099, code lost:
    
        r10.put(r2, r4);
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x009c, code lost:
    
        r0.h(r1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x009f, code lost:
    
        return;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void t(java.lang.Object r9, int r10, java.lang.Object r11, com.google.protobuf.C4020n r12, com.google.protobuf.C4015i r13) throws com.google.protobuf.InvalidProtocolBufferException.InvalidWireTypeException {
        /*
            r8 = this;
            int r10 = r8.O(r10)
            r0 = 1048575(0xfffff, float:1.469367E-39)
            r10 = r10 & r0
            long r0 = (long) r10
            com.google.protobuf.s0 r10 = com.google.protobuf.t0.c
            java.lang.Object r10 = r10.i(r0, r9)
            com.google.protobuf.O r2 = r8.m
            if (r10 != 0) goto L20
            r2.getClass()
            com.google.protobuf.N r10 = com.google.protobuf.N.b
            com.google.protobuf.N r10 = r10.e()
            com.google.protobuf.t0.p(r0, r9, r10)
            goto L37
        L20:
            r2.getClass()
            r3 = r10
            com.google.protobuf.N r3 = (com.google.protobuf.N) r3
            boolean r3 = r3.a
            if (r3 != 0) goto L37
            com.google.protobuf.N r3 = com.google.protobuf.N.b
            com.google.protobuf.N r3 = r3.e()
            com.google.protobuf.O.a(r3, r10)
            com.google.protobuf.t0.p(r0, r9, r3)
            r10 = r3
        L37:
            r2.getClass()
            com.google.protobuf.N r10 = (com.google.protobuf.N) r10
            com.google.protobuf.M r11 = (com.google.protobuf.M) r11
            com.google.protobuf.L r9 = r11.a
            r11 = 2
            r13.w(r11)
            androidx.core.view.f0 r0 = r13.a
            int r1 = r0.C()
            int r1 = r0.i(r1)
            java.lang.String r2 = ""
            java.lang.Object r3 = r9.c
            r4 = r3
        L53:
            int r5 = r13.a()     // Catch: java.lang.Throwable -> L77
            r6 = 2147483647(0x7fffffff, float:NaN)
            if (r5 == r6) goto L99
            boolean r6 = r0.c()     // Catch: java.lang.Throwable -> L77
            if (r6 == 0) goto L63
            goto L99
        L63:
            r6 = 1
            java.lang.String r7 = "Unable to parse map entry."
            if (r5 == r6) goto L84
            if (r5 == r11) goto L79
            boolean r5 = r13.x()     // Catch: java.lang.Throwable -> L77 com.google.protobuf.InvalidProtocolBufferException.InvalidWireTypeException -> L8c
            if (r5 == 0) goto L71
            goto L53
        L71:
            com.google.protobuf.InvalidProtocolBufferException r5 = new com.google.protobuf.InvalidProtocolBufferException     // Catch: java.lang.Throwable -> L77 com.google.protobuf.InvalidProtocolBufferException.InvalidWireTypeException -> L8c
            r5.<init>(r7)     // Catch: java.lang.Throwable -> L77 com.google.protobuf.InvalidProtocolBufferException.InvalidWireTypeException -> L8c
            throw r5     // Catch: java.lang.Throwable -> L77 com.google.protobuf.InvalidProtocolBufferException.InvalidWireTypeException -> L8c
        L77:
            r9 = move-exception
            goto La0
        L79:
            com.google.protobuf.B0 r5 = r9.b     // Catch: java.lang.Throwable -> L77 com.google.protobuf.InvalidProtocolBufferException.InvalidWireTypeException -> L8c
            java.lang.Class r6 = r3.getClass()     // Catch: java.lang.Throwable -> L77 com.google.protobuf.InvalidProtocolBufferException.InvalidWireTypeException -> L8c
            java.lang.Object r4 = r13.i(r5, r6, r12)     // Catch: java.lang.Throwable -> L77 com.google.protobuf.InvalidProtocolBufferException.InvalidWireTypeException -> L8c
            goto L53
        L84:
            com.google.protobuf.x0 r5 = r9.a     // Catch: java.lang.Throwable -> L77 com.google.protobuf.InvalidProtocolBufferException.InvalidWireTypeException -> L8c
            r6 = 0
            java.lang.Object r2 = r13.i(r5, r6, r6)     // Catch: java.lang.Throwable -> L77 com.google.protobuf.InvalidProtocolBufferException.InvalidWireTypeException -> L8c
            goto L53
        L8c:
            boolean r5 = r13.x()     // Catch: java.lang.Throwable -> L77
            if (r5 == 0) goto L93
            goto L53
        L93:
            com.google.protobuf.InvalidProtocolBufferException r9 = new com.google.protobuf.InvalidProtocolBufferException     // Catch: java.lang.Throwable -> L77
            r9.<init>(r7)     // Catch: java.lang.Throwable -> L77
            throw r9     // Catch: java.lang.Throwable -> L77
        L99:
            r10.put(r2, r4)     // Catch: java.lang.Throwable -> L77
            r0.h(r1)
            return
        La0:
            r0.h(r1)
            throw r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.protobuf.T.t(java.lang.Object, int, java.lang.Object, com.google.protobuf.n, com.google.protobuf.i):void");
    }

    public final void u(int i, Object obj, Object obj2) {
        if (o(i, obj2)) {
            long jO = O(i) & 1048575;
            Unsafe unsafe = o;
            Object object = unsafe.getObject(obj2, jO);
            if (object == null) {
                throw new IllegalStateException("Source subfield " + this.a[i] + " is present but null: " + obj2);
            }
            InterfaceC4009c0 interfaceC4009c0N = n(i);
            if (!o(i, obj)) {
                if (q(object)) {
                    AbstractC4027v abstractC4027vD = interfaceC4009c0N.d();
                    interfaceC4009c0N.a(abstractC4027vD, object);
                    unsafe.putObject(obj, jO, abstractC4027vD);
                } else {
                    unsafe.putObject(obj, jO, object);
                }
                J(i, obj);
                return;
            }
            Object object2 = unsafe.getObject(obj, jO);
            if (!q(object2)) {
                AbstractC4027v abstractC4027vD2 = interfaceC4009c0N.d();
                interfaceC4009c0N.a(abstractC4027vD2, object2);
                unsafe.putObject(obj, jO, abstractC4027vD2);
                object2 = abstractC4027vD2;
            }
            interfaceC4009c0N.a(object2, object);
        }
    }

    public final void v(int i, Object obj, Object obj2) {
        int[] iArr = this.a;
        int i2 = iArr[i];
        if (r(i2, i, obj2)) {
            long jO = O(i) & 1048575;
            Unsafe unsafe = o;
            Object object = unsafe.getObject(obj2, jO);
            if (object == null) {
                throw new IllegalStateException("Source subfield " + iArr[i] + " is present but null: " + obj2);
            }
            InterfaceC4009c0 interfaceC4009c0N = n(i);
            if (!r(i2, i, obj)) {
                if (q(object)) {
                    AbstractC4027v abstractC4027vD = interfaceC4009c0N.d();
                    interfaceC4009c0N.a(abstractC4027vD, object);
                    unsafe.putObject(obj, jO, abstractC4027vD);
                } else {
                    unsafe.putObject(obj, jO, object);
                }
                K(i2, i, obj);
                return;
            }
            Object object2 = unsafe.getObject(obj, jO);
            if (!q(object2)) {
                AbstractC4027v abstractC4027vD2 = interfaceC4009c0N.d();
                interfaceC4009c0N.a(abstractC4027vD2, object2);
                unsafe.putObject(obj, jO, abstractC4027vD2);
                object2 = abstractC4027vD2;
            }
            interfaceC4009c0N.a(object2, object);
        }
    }

    public final Object w(int i, Object obj) {
        InterfaceC4009c0 interfaceC4009c0N = n(i);
        long jO = O(i) & 1048575;
        if (!o(i, obj)) {
            return interfaceC4009c0N.d();
        }
        Object object = o.getObject(obj, jO);
        if (q(object)) {
            return object;
        }
        AbstractC4027v abstractC4027vD = interfaceC4009c0N.d();
        if (object != null) {
            interfaceC4009c0N.a(abstractC4027vD, object);
        }
        return abstractC4027vD;
    }

    public final Object x(int i, int i2, Object obj) {
        InterfaceC4009c0 interfaceC4009c0N = n(i2);
        if (!r(i, i2, obj)) {
            return interfaceC4009c0N.d();
        }
        Object object = o.getObject(obj, O(i2) & 1048575);
        if (q(object)) {
            return object;
        }
        AbstractC4027v abstractC4027vD = interfaceC4009c0N.d();
        if (object != null) {
            interfaceC4009c0N.a(abstractC4027vD, object);
        }
        return abstractC4027vD;
    }
}
