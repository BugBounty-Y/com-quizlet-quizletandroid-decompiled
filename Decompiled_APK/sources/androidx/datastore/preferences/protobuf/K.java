package androidx.datastore.preferences.protobuf;

import androidx.core.view.AbstractC1047f0;
import androidx.datastore.preferences.protobuf.InvalidProtocolBufferException;
import com.appsflyer.attribution.RequestError;
import com.comscore.streaming.EventType;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import sun.misc.Unsafe;

/* loaded from: classes.dex */
public final class K implements U {
    public static final int[] n = new int[0];
    public static final Unsafe o = g0.i();
    public final int[] a;
    public final Object[] b;
    public final int c;
    public final int d;
    public final AbstractC1113u e;
    public final boolean f;
    public final int[] g;
    public final int h;
    public final int i;
    public final M j;
    public final C1118z k;
    public final Z l;
    public final G m;

    public K(int[] iArr, Object[] objArr, int i, int i2, AbstractC1113u abstractC1113u, int[] iArr2, int i3, int i4, M m, C1118z c1118z, Z z, C1107n c1107n, G g) {
        this.a = iArr;
        this.b = objArr;
        this.c = i;
        this.d = i2;
        this.f = Objects.nonNull(abstractC1113u);
        this.g = iArr2;
        this.h = i3;
        this.i = i4;
        this.j = m;
        this.k = c1118z;
        this.l = z;
        this.e = abstractC1113u;
        this.m = g;
    }

    public static long A(long j, Object obj) {
        return ((Long) g0.c.h(j, obj)).longValue();
    }

    public static Field G(Class cls, String str) {
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

    public static int L(int i) {
        return (i & 267386880) >>> 20;
    }

    public static boolean p(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj instanceof AbstractC1113u) {
            return ((AbstractC1113u) obj).g();
        }
        return true;
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
    public static androidx.datastore.preferences.protobuf.K x(androidx.datastore.preferences.protobuf.T r34, androidx.datastore.preferences.protobuf.M r35, androidx.datastore.preferences.protobuf.C1118z r36, androidx.datastore.preferences.protobuf.Z r37, androidx.datastore.preferences.protobuf.C1107n r38, androidx.datastore.preferences.protobuf.G r39) {
        /*
            Method dump skipped, instructions count: 1023
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.preferences.protobuf.K.x(androidx.datastore.preferences.protobuf.T, androidx.datastore.preferences.protobuf.M, androidx.datastore.preferences.protobuf.z, androidx.datastore.preferences.protobuf.Z, androidx.datastore.preferences.protobuf.n, androidx.datastore.preferences.protobuf.G):androidx.datastore.preferences.protobuf.K");
    }

    public static long y(int i) {
        return i & 1048575;
    }

    public static int z(long j, Object obj) {
        return ((Integer) g0.c.h(j, obj)).intValue();
    }

    public final int B(int i) {
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

    public final void C(Object obj, long j, C1103j c1103j, U u, C1106m c1106m) throws InvalidProtocolBufferException.InvalidWireTypeException {
        int iB;
        this.k.getClass();
        InterfaceC1114v interfaceC1114vA = C1118z.a(j, obj);
        int i = c1103j.b;
        if ((i & 7) != 3) {
            throw InvalidProtocolBufferException.b();
        }
        do {
            AbstractC1113u abstractC1113uD = u.d();
            c1103j.b(abstractC1113uD, u, c1106m);
            u.b(abstractC1113uD);
            ((S) interfaceC1114vA).add(abstractC1113uD);
            AbstractC1047f0 abstractC1047f0 = c1103j.a;
            if (abstractC1047f0.c() || c1103j.d != 0) {
                return;
            } else {
                iB = abstractC1047f0.B();
            }
        } while (iB == i);
        c1103j.d = iB;
    }

    public final void D(Object obj, int i, C1103j c1103j, U u, C1106m c1106m) throws InvalidProtocolBufferException {
        int iB;
        this.k.getClass();
        InterfaceC1114v interfaceC1114vA = C1118z.a(i & 1048575, obj);
        int i2 = c1103j.b;
        if ((i2 & 7) != 2) {
            throw InvalidProtocolBufferException.b();
        }
        do {
            AbstractC1113u abstractC1113uD = u.d();
            c1103j.c(abstractC1113uD, u, c1106m);
            u.b(abstractC1113uD);
            ((S) interfaceC1114vA).add(abstractC1113uD);
            AbstractC1047f0 abstractC1047f0 = c1103j.a;
            if (abstractC1047f0.c() || c1103j.d != 0) {
                return;
            } else {
                iB = abstractC1047f0.B();
            }
        } while (iB == i2);
        c1103j.d = iB;
    }

    public final void E(int i, C1103j c1103j, Object obj) throws InvalidProtocolBufferException.InvalidWireTypeException {
        if ((536870912 & i) != 0) {
            c1103j.w(2);
            g0.o(i & 1048575, obj, c1103j.a.A());
        } else if (!this.f) {
            g0.o(i & 1048575, obj, c1103j.e());
        } else {
            c1103j.w(2);
            g0.o(i & 1048575, obj, c1103j.a.z());
        }
    }

    public final void F(int i, C1103j c1103j, Object obj) throws InvalidProtocolBufferException.InvalidWireTypeException {
        boolean z = (536870912 & i) != 0;
        C1118z c1118z = this.k;
        if (z) {
            c1118z.getClass();
            c1103j.s(C1118z.a(i & 1048575, obj), true);
        } else {
            c1118z.getClass();
            c1103j.s(C1118z.a(i & 1048575, obj), false);
        }
    }

    public final void H(int i, Object obj) {
        int i2 = this.a[i + 2];
        long j = 1048575 & i2;
        if (j == 1048575) {
            return;
        }
        g0.m(j, obj, (1 << (i2 >>> 20)) | g0.c.f(j, obj));
    }

    public final void I(int i, int i2, Object obj) {
        g0.m(this.a[i2 + 2] & 1048575, obj, i);
    }

    public final void J(Object obj, int i, AbstractC1094a abstractC1094a) {
        o.putObject(obj, M(i) & 1048575, abstractC1094a);
        H(i, obj);
    }

    public final void K(Object obj, int i, int i2, AbstractC1094a abstractC1094a) {
        o.putObject(obj, M(i2) & 1048575, abstractC1094a);
        I(i, i2, obj);
    }

    public final int M(int i) {
        return this.a[i + 1];
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    public final void N(Object obj, C c) throws IOException {
        int i;
        int i2;
        int i3;
        int i4;
        int i5;
        int i6;
        boolean z;
        K k = this;
        int i7 = 2;
        int[] iArr = k.a;
        int length = iArr.length;
        Unsafe unsafe = o;
        int i8 = 1048575;
        int i9 = 1048575;
        int i10 = 0;
        int i11 = 0;
        while (i10 < length) {
            int iM = k.M(i10);
            int i12 = iArr[i10];
            int iL = L(iM);
            if (iL <= 17) {
                int i13 = iArr[i10 + 2];
                i = 1;
                int i14 = i13 & i8;
                if (i14 != i9) {
                    i11 = i14 == i8 ? 0 : unsafe.getInt(obj, i14);
                    i9 = i14;
                }
                i2 = iM;
                i3 = 1 << (i13 >>> 20);
            } else {
                i = 1;
                i2 = iM;
                i3 = 0;
            }
            int i15 = i7;
            long j = i2 & i8;
            switch (iL) {
                case 0:
                    if (k.o(obj, i10, i9, i11, i3)) {
                        double d = g0.c.d(j, obj);
                        C1104k c1104k = (C1104k) c.a;
                        c1104k.getClass();
                        c1104k.v(i12, Double.doubleToRawLongBits(d));
                        break;
                    } else {
                        break;
                    }
                case 1:
                    if (k.o(obj, i10, i9, i11, i3)) {
                        float fE = g0.c.e(j, obj);
                        C1104k c1104k2 = (C1104k) c.a;
                        c1104k2.getClass();
                        c1104k2.t(i12, Float.floatToRawIntBits(fE));
                    }
                    k = this;
                    break;
                case 2:
                    if (k.o(obj, i10, i9, i11, i3)) {
                        ((C1104k) c.a).F(i12, unsafe.getLong(obj, j));
                    }
                    k = this;
                    break;
                case 3:
                    if (k.o(obj, i10, i9, i11, i3)) {
                        ((C1104k) c.a).F(i12, unsafe.getLong(obj, j));
                    }
                    k = this;
                    break;
                case 4:
                    if (k.o(obj, i10, i9, i11, i3)) {
                        ((C1104k) c.a).x(i12, unsafe.getInt(obj, j));
                    }
                    k = this;
                    break;
                case 5:
                    if (k.o(obj, i10, i9, i11, i3)) {
                        ((C1104k) c.a).v(i12, unsafe.getLong(obj, j));
                    }
                    k = this;
                    break;
                case 6:
                    if (k.o(obj, i10, i9, i11, i3)) {
                        ((C1104k) c.a).t(i12, unsafe.getInt(obj, j));
                    }
                    k = this;
                    break;
                case 7:
                    if (k.o(obj, i10, i9, i11, i3)) {
                        ((C1104k) c.a).q(i12, g0.c.c(j, obj));
                    }
                    k = this;
                    break;
                case 8:
                    if (k.o(obj, i10, i9, i11, i3)) {
                        Object object = unsafe.getObject(obj, j);
                        if (object instanceof String) {
                            ((C1104k) c.a).A(i12, (String) object);
                        } else {
                            ((C1104k) c.a).r(i12, (C1100g) object);
                        }
                    }
                    k = this;
                    break;
                case 9:
                    if (k.o(obj, i10, i9, i11, i3)) {
                        ((C1104k) c.a).z(i12, (AbstractC1094a) unsafe.getObject(obj, j), k.m(i10));
                        break;
                    } else {
                        break;
                    }
                case 10:
                    if (k.o(obj, i10, i9, i11, i3)) {
                        ((C1104k) c.a).r(i12, (C1100g) unsafe.getObject(obj, j));
                    }
                    k = this;
                    break;
                case 11:
                    if (k.o(obj, i10, i9, i11, i3)) {
                        ((C1104k) c.a).D(i12, unsafe.getInt(obj, j));
                    }
                    k = this;
                    break;
                case 12:
                    if (k.o(obj, i10, i9, i11, i3)) {
                        ((C1104k) c.a).x(i12, unsafe.getInt(obj, j));
                    }
                    k = this;
                    break;
                case 13:
                    if (k.o(obj, i10, i9, i11, i3)) {
                        ((C1104k) c.a).t(i12, unsafe.getInt(obj, j));
                    }
                    k = this;
                    break;
                case 14:
                    if (k.o(obj, i10, i9, i11, i3)) {
                        ((C1104k) c.a).v(i12, unsafe.getLong(obj, j));
                    }
                    k = this;
                    break;
                case 15:
                    if (k.o(obj, i10, i9, i11, i3)) {
                        int i16 = unsafe.getInt(obj, j);
                        ((C1104k) c.a).D(i12, (i16 >> 31) ^ (i16 << 1));
                    }
                    k = this;
                    break;
                case 16:
                    if (k.o(obj, i10, i9, i11, i3)) {
                        long j2 = unsafe.getLong(obj, j);
                        ((C1104k) c.a).F(i12, (j2 >> 63) ^ (j2 << 1));
                    }
                    k = this;
                    break;
                case 17:
                    if (k.o(obj, i10, i9, i11, i3)) {
                        c.a(i12, unsafe.getObject(obj, j), k.m(i10));
                    }
                    break;
                case 18:
                    i4 = i9;
                    V.n(iArr[i10], (List) unsafe.getObject(obj, j), c, false);
                    i9 = i4;
                    break;
                case 19:
                    i4 = i9;
                    V.r(iArr[i10], (List) unsafe.getObject(obj, j), c, false);
                    i9 = i4;
                    break;
                case 20:
                    i4 = i9;
                    V.t(iArr[i10], (List) unsafe.getObject(obj, j), c, false);
                    i9 = i4;
                    break;
                case 21:
                    i4 = i9;
                    V.z(iArr[i10], (List) unsafe.getObject(obj, j), c, false);
                    i9 = i4;
                    break;
                case EventType.WINDOW_STATE /* 22 */:
                    i4 = i9;
                    V.s(iArr[i10], (List) unsafe.getObject(obj, j), c, false);
                    i9 = i4;
                    break;
                case EventType.AUDIO /* 23 */:
                    i4 = i9;
                    V.q(iArr[i10], (List) unsafe.getObject(obj, j), c, false);
                    i9 = i4;
                    break;
                case EventType.VIDEO /* 24 */:
                    i4 = i9;
                    V.p(iArr[i10], (List) unsafe.getObject(obj, j), c, false);
                    i9 = i4;
                    break;
                case EventType.SUBS /* 25 */:
                    i4 = i9;
                    V.m(iArr[i10], (List) unsafe.getObject(obj, j), c, false);
                    i9 = i4;
                    break;
                case EventType.CDN /* 26 */:
                    i5 = i9;
                    int i17 = iArr[i10];
                    List list = (List) unsafe.getObject(obj, j);
                    Class cls = V.a;
                    if (list != null && !list.isEmpty()) {
                        c.getClass();
                        for (int i18 = 0; i18 < list.size(); i18++) {
                            ((C1104k) c.a).A(i17, (String) list.get(i18));
                        }
                    }
                    i9 = i5;
                    break;
                case 27:
                    i5 = i9;
                    int i19 = iArr[i10];
                    List list2 = (List) unsafe.getObject(obj, j);
                    U uM = k.m(i10);
                    Class cls2 = V.a;
                    if (list2 != null && !list2.isEmpty()) {
                        c.getClass();
                        for (int i20 = 0; i20 < list2.size(); i20++) {
                            ((C1104k) c.a).z(i19, (AbstractC1094a) list2.get(i20), uM);
                        }
                    }
                    i9 = i5;
                    break;
                case 28:
                    i5 = i9;
                    int i21 = iArr[i10];
                    List list3 = (List) unsafe.getObject(obj, j);
                    Class cls3 = V.a;
                    if (list3 != null && !list3.isEmpty()) {
                        c.getClass();
                        for (int i22 = 0; i22 < list3.size(); i22++) {
                            ((C1104k) c.a).r(i21, (C1100g) list3.get(i22));
                        }
                    }
                    i9 = i5;
                    break;
                case 29:
                    i4 = i9;
                    V.y(iArr[i10], (List) unsafe.getObject(obj, j), c, false);
                    i9 = i4;
                    break;
                case 30:
                    i4 = i9;
                    V.o(iArr[i10], (List) unsafe.getObject(obj, j), c, false);
                    i9 = i4;
                    break;
                case 31:
                    i4 = i9;
                    V.u(iArr[i10], (List) unsafe.getObject(obj, j), c, false);
                    i9 = i4;
                    break;
                case 32:
                    i4 = i9;
                    V.v(iArr[i10], (List) unsafe.getObject(obj, j), c, false);
                    i9 = i4;
                    break;
                case 33:
                    i4 = i9;
                    V.w(iArr[i10], (List) unsafe.getObject(obj, j), c, false);
                    i9 = i4;
                    break;
                case 34:
                    i4 = i9;
                    V.x(iArr[i10], (List) unsafe.getObject(obj, j), c, false);
                    i9 = i4;
                    break;
                case 35:
                    i6 = i9;
                    z = i == true ? 1 : 0;
                    V.n(iArr[i10], (List) unsafe.getObject(obj, j), c, z);
                    i9 = i6;
                    break;
                case 36:
                    i6 = i9;
                    z = i == true ? 1 : 0;
                    V.r(iArr[i10], (List) unsafe.getObject(obj, j), c, z);
                    i9 = i6;
                    break;
                case 37:
                    i6 = i9;
                    z = i == true ? 1 : 0;
                    V.t(iArr[i10], (List) unsafe.getObject(obj, j), c, z);
                    i9 = i6;
                    break;
                case 38:
                    i6 = i9;
                    z = i == true ? 1 : 0;
                    V.z(iArr[i10], (List) unsafe.getObject(obj, j), c, z);
                    i9 = i6;
                    break;
                case 39:
                    i6 = i9;
                    z = i == true ? 1 : 0;
                    V.s(iArr[i10], (List) unsafe.getObject(obj, j), c, z);
                    i9 = i6;
                    break;
                case RequestError.NETWORK_FAILURE /* 40 */:
                    i6 = i9;
                    z = i == true ? 1 : 0;
                    V.q(iArr[i10], (List) unsafe.getObject(obj, j), c, z);
                    i9 = i6;
                    break;
                case RequestError.NO_DEV_KEY /* 41 */:
                    i6 = i9;
                    z = i == true ? 1 : 0;
                    V.p(iArr[i10], (List) unsafe.getObject(obj, j), c, z);
                    i9 = i6;
                    break;
                case 42:
                    i6 = i9;
                    z = i == true ? 1 : 0;
                    V.m(iArr[i10], (List) unsafe.getObject(obj, j), c, z);
                    i9 = i6;
                    break;
                case 43:
                    i6 = i9;
                    z = i == true ? 1 : 0;
                    V.y(iArr[i10], (List) unsafe.getObject(obj, j), c, z);
                    i9 = i6;
                    break;
                case 44:
                    i6 = i9;
                    z = i == true ? 1 : 0;
                    V.o(iArr[i10], (List) unsafe.getObject(obj, j), c, z);
                    i9 = i6;
                    break;
                case 45:
                    i6 = i9;
                    z = i == true ? 1 : 0;
                    V.u(iArr[i10], (List) unsafe.getObject(obj, j), c, z);
                    i9 = i6;
                    break;
                case 46:
                    i6 = i9;
                    z = i == true ? 1 : 0;
                    V.v(iArr[i10], (List) unsafe.getObject(obj, j), c, z);
                    i9 = i6;
                    break;
                case 47:
                    i6 = i9;
                    z = i == true ? 1 : 0;
                    V.w(iArr[i10], (List) unsafe.getObject(obj, j), c, z);
                    i9 = i6;
                    break;
                case 48:
                    i6 = i9;
                    z = i == true ? 1 : 0;
                    V.x(iArr[i10], (List) unsafe.getObject(obj, j), c, z);
                    i9 = i6;
                    break;
                case 49:
                    i6 = i9;
                    int i23 = iArr[i10];
                    List list4 = (List) unsafe.getObject(obj, j);
                    U uM2 = k.m(i10);
                    Class cls4 = V.a;
                    if (list4 != null && !list4.isEmpty()) {
                        c.getClass();
                        for (int i24 = 0; i24 < list4.size(); i24++) {
                            c.a(i23, list4.get(i24), uM2);
                        }
                    }
                    z = true;
                    i9 = i6;
                    break;
                case RequestError.RESPONSE_CODE_FAILURE /* 50 */:
                    Object object2 = unsafe.getObject(obj, j);
                    if (object2 != null) {
                        Object obj2 = k.b[(i10 / 3) * i15];
                        k.m.getClass();
                        D d2 = ((E) obj2).a;
                        C1104k c1104k3 = (C1104k) c.a;
                        c1104k3.getClass();
                        for (Map.Entry entry : ((F) object2).entrySet()) {
                            c1104k3.C(i12, i15);
                            c1104k3.E(E.a(d2, entry.getKey(), entry.getValue()));
                            Object key = entry.getKey();
                            Object value = entry.getValue();
                            C1109p.b(c1104k3, d2.a, i, key);
                            i15 = 2;
                            C1109p.b(c1104k3, d2.b, 2, value);
                            i9 = i9;
                            i = 1;
                        }
                    }
                    i5 = i9;
                    i9 = i5;
                    break;
                case 51:
                    if (k.q(i12, i10, obj)) {
                        double dDoubleValue = ((Double) g0.c.h(j, obj)).doubleValue();
                        C1104k c1104k4 = (C1104k) c.a;
                        c1104k4.getClass();
                        c1104k4.v(i12, Double.doubleToRawLongBits(dDoubleValue));
                    }
                    break;
                case 52:
                    if (k.q(i12, i10, obj)) {
                        float fFloatValue = ((Float) g0.c.h(j, obj)).floatValue();
                        C1104k c1104k5 = (C1104k) c.a;
                        c1104k5.getClass();
                        c1104k5.t(i12, Float.floatToRawIntBits(fFloatValue));
                    }
                    break;
                case 53:
                    if (k.q(i12, i10, obj)) {
                        ((C1104k) c.a).F(i12, A(j, obj));
                    }
                    break;
                case 54:
                    if (k.q(i12, i10, obj)) {
                        ((C1104k) c.a).F(i12, A(j, obj));
                    }
                    break;
                case 55:
                    if (k.q(i12, i10, obj)) {
                        ((C1104k) c.a).x(i12, z(j, obj));
                    }
                    break;
                case 56:
                    if (k.q(i12, i10, obj)) {
                        ((C1104k) c.a).v(i12, A(j, obj));
                    }
                    break;
                case 57:
                    if (k.q(i12, i10, obj)) {
                        ((C1104k) c.a).t(i12, z(j, obj));
                    }
                    break;
                case 58:
                    if (k.q(i12, i10, obj)) {
                        ((C1104k) c.a).q(i12, ((Boolean) g0.c.h(j, obj)).booleanValue());
                    }
                    break;
                case 59:
                    if (k.q(i12, i10, obj)) {
                        Object object3 = unsafe.getObject(obj, j);
                        if (object3 instanceof String) {
                            ((C1104k) c.a).A(i12, (String) object3);
                        } else {
                            ((C1104k) c.a).r(i12, (C1100g) object3);
                        }
                    }
                    break;
                case 60:
                    if (k.q(i12, i10, obj)) {
                        ((C1104k) c.a).z(i12, (AbstractC1094a) unsafe.getObject(obj, j), k.m(i10));
                    }
                    break;
                case 61:
                    if (k.q(i12, i10, obj)) {
                        ((C1104k) c.a).r(i12, (C1100g) unsafe.getObject(obj, j));
                    }
                    break;
                case 62:
                    if (k.q(i12, i10, obj)) {
                        ((C1104k) c.a).D(i12, z(j, obj));
                    }
                    break;
                case 63:
                    if (k.q(i12, i10, obj)) {
                        ((C1104k) c.a).x(i12, z(j, obj));
                    }
                    break;
                case 64:
                    if (k.q(i12, i10, obj)) {
                        ((C1104k) c.a).t(i12, z(j, obj));
                    }
                    break;
                case 65:
                    if (k.q(i12, i10, obj)) {
                        ((C1104k) c.a).v(i12, A(j, obj));
                    }
                    break;
                case 66:
                    if (k.q(i12, i10, obj)) {
                        int iZ = z(j, obj);
                        ((C1104k) c.a).D(i12, (iZ >> 31) ^ (iZ << 1));
                    }
                    break;
                case 67:
                    if (k.q(i12, i10, obj)) {
                        long jA = A(j, obj);
                        ((C1104k) c.a).F(i12, (jA << (i == true ? 1L : 0L)) ^ (jA >> 63));
                    }
                    break;
                case 68:
                    if (k.q(i12, i10, obj)) {
                        c.a(i12, unsafe.getObject(obj, j), k.m(i10));
                    }
                    break;
            }
            i10 += 3;
            i7 = i15;
            i8 = 1048575;
        }
        ((b0) k.l).getClass();
        ((AbstractC1113u) obj).unknownFields.d(c);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:11:0x0025  */
    @Override // androidx.datastore.preferences.protobuf.U
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(java.lang.Object r11, java.lang.Object r12) {
        /*
            Method dump skipped, instructions count: 662
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.preferences.protobuf.K.a(java.lang.Object, java.lang.Object):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x0080  */
    @Override // androidx.datastore.preferences.protobuf.U
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(java.lang.Object r10) {
        /*
            r9 = this;
            boolean r0 = p(r10)
            if (r0 != 0) goto L8
            goto La7
        L8:
            boolean r0 = r10 instanceof androidx.datastore.preferences.protobuf.AbstractC1113u
            r1 = 0
            if (r0 == 0) goto L1b
            r0 = r10
            androidx.datastore.preferences.protobuf.u r0 = (androidx.datastore.preferences.protobuf.AbstractC1113u) r0
            r2 = 2147483647(0x7fffffff, float:NaN)
            r0.k(r2)
            r0.memoizedHashCode = r1
            r0.h()
        L1b:
            int[] r0 = r9.a
            int r2 = r0.length
            r3 = r1
        L1f:
            if (r3 >= r2) goto L96
            int r4 = r9.M(r3)
            r5 = 1048575(0xfffff, float:1.469367E-39)
            r5 = r5 & r4
            long r5 = (long) r5
            int r4 = L(r4)
            r7 = 9
            if (r4 == r7) goto L80
            r7 = 60
            if (r4 == r7) goto L6a
            r7 = 68
            if (r4 == r7) goto L6a
            switch(r4) {
                case 17: goto L80;
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
            goto L93
        L3e:
            sun.misc.Unsafe r4 = androidx.datastore.preferences.protobuf.K.o
            java.lang.Object r7 = r4.getObject(r10, r5)
            if (r7 == 0) goto L93
            androidx.datastore.preferences.protobuf.G r8 = r9.m
            r8.getClass()
            r8 = r7
            androidx.datastore.preferences.protobuf.F r8 = (androidx.datastore.preferences.protobuf.F) r8
            r8.a = r1
            r4.putObject(r10, r5, r7)
            goto L93
        L54:
            androidx.datastore.preferences.protobuf.z r4 = r9.k
            r4.getClass()
            androidx.datastore.preferences.protobuf.f0 r4 = androidx.datastore.preferences.protobuf.g0.c
            java.lang.Object r4 = r4.h(r5, r10)
            androidx.datastore.preferences.protobuf.v r4 = (androidx.datastore.preferences.protobuf.InterfaceC1114v) r4
            androidx.datastore.preferences.protobuf.b r4 = (androidx.datastore.preferences.protobuf.AbstractC1095b) r4
            boolean r5 = r4.a
            if (r5 == 0) goto L93
            r4.a = r1
            goto L93
        L6a:
            r4 = r0[r3]
            boolean r4 = r9.q(r4, r3, r10)
            if (r4 == 0) goto L93
            androidx.datastore.preferences.protobuf.U r4 = r9.m(r3)
            sun.misc.Unsafe r7 = androidx.datastore.preferences.protobuf.K.o
            java.lang.Object r5 = r7.getObject(r10, r5)
            r4.b(r5)
            goto L93
        L80:
            boolean r4 = r9.n(r3, r10)
            if (r4 == 0) goto L93
            androidx.datastore.preferences.protobuf.U r4 = r9.m(r3)
            sun.misc.Unsafe r7 = androidx.datastore.preferences.protobuf.K.o
            java.lang.Object r5 = r7.getObject(r10, r5)
            r4.b(r5)
        L93:
            int r3 = r3 + 3
            goto L1f
        L96:
            androidx.datastore.preferences.protobuf.Z r0 = r9.l
            androidx.datastore.preferences.protobuf.b0 r0 = (androidx.datastore.preferences.protobuf.b0) r0
            r0.getClass()
            androidx.datastore.preferences.protobuf.u r10 = (androidx.datastore.preferences.protobuf.AbstractC1113u) r10
            androidx.datastore.preferences.protobuf.a0 r10 = r10.unknownFields
            boolean r0 = r10.e
            if (r0 == 0) goto La7
            r10.e = r1
        La7:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.preferences.protobuf.K.b(java.lang.Object):void");
    }

    @Override // androidx.datastore.preferences.protobuf.U
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
            int iM = M(i7);
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
            if ((268435456 & iM) == 0 || o(obj, i2, i, i3, i11)) {
                int iL = L(iM);
                if (iL == 9 || iL == 17) {
                    if (o(obj, i2, i, i3, i11)) {
                        if (!m(i2).c(g0.c.h(iM & 1048575, obj))) {
                        }
                    } else {
                        continue;
                    }
                    i6++;
                    i4 = i;
                    i5 = i3;
                } else {
                    if (iL != 27) {
                        if (iL == 60 || iL == 68) {
                            if (q(i8, i2, obj)) {
                                if (!m(i2).c(g0.c.h(iM & 1048575, obj))) {
                                }
                            } else {
                                continue;
                            }
                            i6++;
                            i4 = i;
                            i5 = i3;
                        } else if (iL != 49) {
                            if (iL != 50) {
                                continue;
                            } else {
                                Object objH = g0.c.h(iM & 1048575, obj);
                                this.m.getClass();
                                F f = (F) objH;
                                if (f.isEmpty()) {
                                    continue;
                                } else {
                                    if (((E) this.b[(i2 / 3) * 2]).a.b.a != p0.MESSAGE) {
                                        continue;
                                    } else {
                                        U uA = null;
                                        for (Object obj2 : f.values()) {
                                            if (uA == null) {
                                                uA = Q.c.a(obj2.getClass());
                                            }
                                            if (!uA.c(obj2)) {
                                            }
                                        }
                                    }
                                }
                            }
                            i6++;
                            i4 = i;
                            i5 = i3;
                        }
                    }
                    List list = (List) g0.c.h(iM & 1048575, obj);
                    if (list.isEmpty()) {
                        continue;
                    } else {
                        U uM = m(i2);
                        for (int i13 = 0; i13 < list.size(); i13++) {
                            if (uM.c(list.get(i13))) {
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

    @Override // androidx.datastore.preferences.protobuf.U
    public final AbstractC1113u d() {
        this.j.getClass();
        return this.e.i();
    }

    @Override // androidx.datastore.preferences.protobuf.U
    public final void e(Object obj, C c) throws IOException {
        c.getClass();
        N(obj, c);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:146:0x03b7 A[PHI: r17
  0x03b7: PHI (r17v46 int) = 
  (r17v29 int)
  (r17v30 int)
  (r17v31 int)
  (r17v35 int)
  (r17v37 int)
  (r17v38 int)
  (r17v39 int)
  (r17v43 int)
  (r17v47 int)
 binds: [B:204:0x054c, B:200:0x0530, B:196:0x0514, B:179:0x04a1, B:166:0x043e, B:162:0x0424, B:158:0x040a, B:151:0x03d4, B:145:0x03b5] A[DONT_GENERATE, DONT_INLINE]] */
    @Override // androidx.datastore.preferences.protobuf.U
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int f(androidx.datastore.preferences.protobuf.AbstractC1113u r19) {
        /*
            Method dump skipped, instructions count: 1970
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.preferences.protobuf.K.f(androidx.datastore.preferences.protobuf.u):int");
    }

    /* JADX WARN: Removed duplicated region for block: B:42:0x00e1 A[PHI: r3
  0x00e1: PHI (r3v32 int) = (r3v10 int), (r3v33 int) binds: [B:83:0x0216, B:41:0x00df] A[DONT_GENERATE, DONT_INLINE]] */
    @Override // androidx.datastore.preferences.protobuf.U
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int g(androidx.datastore.preferences.protobuf.AbstractC1113u r12) {
        /*
            Method dump skipped, instructions count: 796
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.preferences.protobuf.K.g(androidx.datastore.preferences.protobuf.u):int");
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x003d  */
    @Override // androidx.datastore.preferences.protobuf.U
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean h(androidx.datastore.preferences.protobuf.AbstractC1113u r12, androidx.datastore.preferences.protobuf.AbstractC1113u r13) {
        /*
            Method dump skipped, instructions count: 666
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.preferences.protobuf.K.h(androidx.datastore.preferences.protobuf.u, androidx.datastore.preferences.protobuf.u):boolean");
    }

    @Override // androidx.datastore.preferences.protobuf.U
    public final void i(Object obj, C1103j c1103j, C1106m c1106m) {
        c1106m.getClass();
        if (!p(obj)) {
            throw new IllegalArgumentException(androidx.compose.ui.node.B.e(obj, "Mutating immutable message: "));
        }
        r(this.l, obj, c1103j, c1106m);
    }

    public final boolean j(AbstractC1113u abstractC1113u, AbstractC1113u abstractC1113u2, int i) {
        return n(i, abstractC1113u) == n(i, abstractC1113u2);
    }

    public final void k(int i, Object obj, Object obj2) {
        int i2 = this.a[i];
        if (g0.c.h(M(i) & 1048575, obj) == null) {
            return;
        }
        l(i);
    }

    public final void l(int i) {
        if (this.b[((i / 3) * 2) + 1] != null) {
            throw new ClassCastException();
        }
    }

    public final U m(int i) {
        int i2 = (i / 3) * 2;
        Object[] objArr = this.b;
        U u = (U) objArr[i2];
        if (u != null) {
            return u;
        }
        U uA = Q.c.a((Class) objArr[i2 + 1]);
        objArr[i2] = uA;
        return uA;
    }

    public final boolean n(int i, Object obj) {
        int i2 = this.a[i + 2];
        long j = i2 & 1048575;
        if (j == 1048575) {
            int iM = M(i);
            long j2 = iM & 1048575;
            switch (L(iM)) {
                case 0:
                    if (Double.doubleToRawLongBits(g0.c.d(j2, obj)) == 0) {
                        return false;
                    }
                    break;
                case 1:
                    if (Float.floatToRawIntBits(g0.c.e(j2, obj)) == 0) {
                        return false;
                    }
                    break;
                case 2:
                    if (g0.c.g(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 3:
                    if (g0.c.g(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 4:
                    if (g0.c.f(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 5:
                    if (g0.c.g(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 6:
                    if (g0.c.f(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 7:
                    return g0.c.c(j2, obj);
                case 8:
                    Object objH = g0.c.h(j2, obj);
                    if (objH instanceof String) {
                        return !((String) objH).isEmpty();
                    }
                    if (objH instanceof C1100g) {
                        return !C1100g.c.equals(objH);
                    }
                    throw new IllegalArgumentException();
                case 9:
                    if (g0.c.h(j2, obj) == null) {
                        return false;
                    }
                    break;
                case 10:
                    return !C1100g.c.equals(g0.c.h(j2, obj));
                case 11:
                    if (g0.c.f(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 12:
                    if (g0.c.f(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 13:
                    if (g0.c.f(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 14:
                    if (g0.c.g(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 15:
                    if (g0.c.f(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 16:
                    if (g0.c.g(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 17:
                    if (g0.c.h(j2, obj) == null) {
                        return false;
                    }
                    break;
                default:
                    throw new IllegalArgumentException();
            }
        } else if (((1 << (i2 >>> 20)) & g0.c.f(j, obj)) == 0) {
            return false;
        }
        return true;
    }

    public final boolean o(Object obj, int i, int i2, int i3, int i4) {
        return i2 == 1048575 ? n(i, obj) : (i3 & i4) != 0;
    }

    public final boolean q(int i, int i2, Object obj) {
        return g0.c.f((long) (this.a[i2 + 2] & 1048575), obj) == i;
    }

    /*  JADX ERROR: Type inference failed
        jadx.core.utils.exceptions.JadxOverflowException: Type inference error: updates count limit reached
        	at jadx.core.utils.ErrorsCounter.addError(ErrorsCounter.java:59)
        	at jadx.core.utils.ErrorsCounter.error(ErrorsCounter.java:31)
        	at jadx.core.dex.attributes.nodes.NotificationAttrNode.addError(NotificationAttrNode.java:19)
        	at jadx.core.dex.visitors.typeinference.TypeInferenceVisitor.visit(TypeInferenceVisitor.java:77)
        */
    public final void r(androidx.datastore.preferences.protobuf.Z r19, java.lang.Object r20, androidx.datastore.preferences.protobuf.C1103j r21, androidx.datastore.preferences.protobuf.C1106m r22) {
        /*
            Method dump skipped, instructions count: 1800
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.preferences.protobuf.K.r(androidx.datastore.preferences.protobuf.Z, java.lang.Object, androidx.datastore.preferences.protobuf.j, androidx.datastore.preferences.protobuf.m):void");
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
    public final void s(java.lang.Object r9, int r10, java.lang.Object r11, androidx.datastore.preferences.protobuf.C1106m r12, androidx.datastore.preferences.protobuf.C1103j r13) throws androidx.datastore.preferences.protobuf.InvalidProtocolBufferException.InvalidWireTypeException {
        /*
            r8 = this;
            int r10 = r8.M(r10)
            r0 = 1048575(0xfffff, float:1.469367E-39)
            r10 = r10 & r0
            long r0 = (long) r10
            androidx.datastore.preferences.protobuf.f0 r10 = androidx.datastore.preferences.protobuf.g0.c
            java.lang.Object r10 = r10.h(r0, r9)
            androidx.datastore.preferences.protobuf.G r2 = r8.m
            if (r10 != 0) goto L20
            r2.getClass()
            androidx.datastore.preferences.protobuf.F r10 = androidx.datastore.preferences.protobuf.F.b
            androidx.datastore.preferences.protobuf.F r10 = r10.d()
            androidx.datastore.preferences.protobuf.g0.o(r0, r9, r10)
            goto L37
        L20:
            r2.getClass()
            r3 = r10
            androidx.datastore.preferences.protobuf.F r3 = (androidx.datastore.preferences.protobuf.F) r3
            boolean r3 = r3.a
            if (r3 != 0) goto L37
            androidx.datastore.preferences.protobuf.F r3 = androidx.datastore.preferences.protobuf.F.b
            androidx.datastore.preferences.protobuf.F r3 = r3.d()
            androidx.datastore.preferences.protobuf.G.a(r3, r10)
            androidx.datastore.preferences.protobuf.g0.o(r0, r9, r3)
            r10 = r3
        L37:
            r2.getClass()
            androidx.datastore.preferences.protobuf.F r10 = (androidx.datastore.preferences.protobuf.F) r10
            androidx.datastore.preferences.protobuf.E r11 = (androidx.datastore.preferences.protobuf.E) r11
            androidx.datastore.preferences.protobuf.D r9 = r11.a
            r11 = 2
            r13.w(r11)
            androidx.core.view.f0 r0 = r13.a
            int r1 = r0.C()
            int r1 = r0.i(r1)
            java.lang.String r2 = ""
            androidx.datastore.preferences.h r3 = r9.c
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
            boolean r5 = r13.x()     // Catch: java.lang.Throwable -> L77 androidx.datastore.preferences.protobuf.InvalidProtocolBufferException.InvalidWireTypeException -> L8c
            if (r5 == 0) goto L71
            goto L53
        L71:
            androidx.datastore.preferences.protobuf.InvalidProtocolBufferException r5 = new androidx.datastore.preferences.protobuf.InvalidProtocolBufferException     // Catch: java.lang.Throwable -> L77 androidx.datastore.preferences.protobuf.InvalidProtocolBufferException.InvalidWireTypeException -> L8c
            r5.<init>(r7)     // Catch: java.lang.Throwable -> L77 androidx.datastore.preferences.protobuf.InvalidProtocolBufferException.InvalidWireTypeException -> L8c
            throw r5     // Catch: java.lang.Throwable -> L77 androidx.datastore.preferences.protobuf.InvalidProtocolBufferException.InvalidWireTypeException -> L8c
        L77:
            r9 = move-exception
            goto La0
        L79:
            androidx.datastore.preferences.protobuf.m0 r5 = r9.b     // Catch: java.lang.Throwable -> L77 androidx.datastore.preferences.protobuf.InvalidProtocolBufferException.InvalidWireTypeException -> L8c
            java.lang.Class r6 = r3.getClass()     // Catch: java.lang.Throwable -> L77 androidx.datastore.preferences.protobuf.InvalidProtocolBufferException.InvalidWireTypeException -> L8c
            java.lang.Object r4 = r13.i(r5, r6, r12)     // Catch: java.lang.Throwable -> L77 androidx.datastore.preferences.protobuf.InvalidProtocolBufferException.InvalidWireTypeException -> L8c
            goto L53
        L84:
            androidx.datastore.preferences.protobuf.k0 r5 = r9.a     // Catch: java.lang.Throwable -> L77 androidx.datastore.preferences.protobuf.InvalidProtocolBufferException.InvalidWireTypeException -> L8c
            r6 = 0
            java.lang.Object r2 = r13.i(r5, r6, r6)     // Catch: java.lang.Throwable -> L77 androidx.datastore.preferences.protobuf.InvalidProtocolBufferException.InvalidWireTypeException -> L8c
            goto L53
        L8c:
            boolean r5 = r13.x()     // Catch: java.lang.Throwable -> L77
            if (r5 == 0) goto L93
            goto L53
        L93:
            androidx.datastore.preferences.protobuf.InvalidProtocolBufferException r9 = new androidx.datastore.preferences.protobuf.InvalidProtocolBufferException     // Catch: java.lang.Throwable -> L77
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
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.preferences.protobuf.K.s(java.lang.Object, int, java.lang.Object, androidx.datastore.preferences.protobuf.m, androidx.datastore.preferences.protobuf.j):void");
    }

    public final void t(int i, Object obj, Object obj2) {
        if (n(i, obj2)) {
            long jM = M(i) & 1048575;
            Unsafe unsafe = o;
            Object object = unsafe.getObject(obj2, jM);
            if (object == null) {
                throw new IllegalStateException("Source subfield " + this.a[i] + " is present but null: " + obj2);
            }
            U uM = m(i);
            if (!n(i, obj)) {
                if (p(object)) {
                    AbstractC1113u abstractC1113uD = uM.d();
                    uM.a(abstractC1113uD, object);
                    unsafe.putObject(obj, jM, abstractC1113uD);
                } else {
                    unsafe.putObject(obj, jM, object);
                }
                H(i, obj);
                return;
            }
            Object object2 = unsafe.getObject(obj, jM);
            if (!p(object2)) {
                AbstractC1113u abstractC1113uD2 = uM.d();
                uM.a(abstractC1113uD2, object2);
                unsafe.putObject(obj, jM, abstractC1113uD2);
                object2 = abstractC1113uD2;
            }
            uM.a(object2, object);
        }
    }

    public final void u(int i, Object obj, Object obj2) {
        int[] iArr = this.a;
        int i2 = iArr[i];
        if (q(i2, i, obj2)) {
            long jM = M(i) & 1048575;
            Unsafe unsafe = o;
            Object object = unsafe.getObject(obj2, jM);
            if (object == null) {
                throw new IllegalStateException("Source subfield " + iArr[i] + " is present but null: " + obj2);
            }
            U uM = m(i);
            if (!q(i2, i, obj)) {
                if (p(object)) {
                    AbstractC1113u abstractC1113uD = uM.d();
                    uM.a(abstractC1113uD, object);
                    unsafe.putObject(obj, jM, abstractC1113uD);
                } else {
                    unsafe.putObject(obj, jM, object);
                }
                I(i2, i, obj);
                return;
            }
            Object object2 = unsafe.getObject(obj, jM);
            if (!p(object2)) {
                AbstractC1113u abstractC1113uD2 = uM.d();
                uM.a(abstractC1113uD2, object2);
                unsafe.putObject(obj, jM, abstractC1113uD2);
                object2 = abstractC1113uD2;
            }
            uM.a(object2, object);
        }
    }

    public final Object v(int i, Object obj) {
        U uM = m(i);
        long jM = M(i) & 1048575;
        if (!n(i, obj)) {
            return uM.d();
        }
        Object object = o.getObject(obj, jM);
        if (p(object)) {
            return object;
        }
        AbstractC1113u abstractC1113uD = uM.d();
        if (object != null) {
            uM.a(abstractC1113uD, object);
        }
        return abstractC1113uD;
    }

    public final Object w(int i, int i2, Object obj) {
        U uM = m(i2);
        if (!q(i, i2, obj)) {
            return uM.d();
        }
        Object object = o.getObject(obj, M(i2) & 1048575);
        if (p(object)) {
            return object;
        }
        AbstractC1113u abstractC1113uD = uM.d();
        if (object != null) {
            uM.a(abstractC1113uD, object);
        }
        return abstractC1113uD;
    }
}
