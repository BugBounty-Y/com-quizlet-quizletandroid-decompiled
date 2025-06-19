package androidx.glance.appwidget.protobuf;

import androidx.core.view.AbstractC1047f0;
import androidx.glance.appwidget.protobuf.InvalidProtocolBufferException;
import com.appsflyer.attribution.RequestError;
import com.comscore.streaming.EventType;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import sun.misc.Unsafe;

/* loaded from: classes.dex */
public final class G implements O {
    public static final int[] n = new int[0];
    public static final Unsafe o = Y.i();
    public final int[] a;
    public final Object[] b;
    public final int c;
    public final int d;
    public final AbstractC1206s e;
    public final boolean f;
    public final int[] g;
    public final int h;
    public final int i;
    public final I j;
    public final C1211x k;
    public final Q l;
    public final C m;

    public G(int[] iArr, Object[] objArr, int i, int i2, AbstractC1206s abstractC1206s, int[] iArr2, int i3, int i4, I i5, C1211x c1211x, Q q, C1201m c1201m, C c) {
        this.a = iArr;
        this.b = objArr;
        this.c = i;
        this.d = i2;
        this.f = Objects.nonNull(abstractC1206s);
        this.g = iArr2;
        this.h = i3;
        this.i = i4;
        this.j = i5;
        this.k = c1211x;
        this.l = q;
        this.e = abstractC1206s;
        this.m = c;
    }

    public static long A(long j, Object obj) {
        return ((Long) Y.c.h(j, obj)).longValue();
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
        if (obj instanceof AbstractC1206s) {
            return ((AbstractC1206s) obj).f();
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
    public static androidx.glance.appwidget.protobuf.G x(androidx.glance.appwidget.protobuf.N r34, androidx.glance.appwidget.protobuf.I r35, androidx.glance.appwidget.protobuf.C1211x r36, androidx.glance.appwidget.protobuf.Q r37, androidx.glance.appwidget.protobuf.C1201m r38, androidx.glance.appwidget.protobuf.C r39) {
        /*
            Method dump skipped, instructions count: 1023
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.appwidget.protobuf.G.x(androidx.glance.appwidget.protobuf.N, androidx.glance.appwidget.protobuf.I, androidx.glance.appwidget.protobuf.x, androidx.glance.appwidget.protobuf.Q, androidx.glance.appwidget.protobuf.m, androidx.glance.appwidget.protobuf.C):androidx.glance.appwidget.protobuf.G");
    }

    public static long y(int i) {
        return i & 1048575;
    }

    public static int z(long j, Object obj) {
        return ((Integer) Y.c.h(j, obj)).intValue();
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

    public final void C(Object obj, long j, C1197i c1197i, O o2, C1200l c1200l) throws InvalidProtocolBufferException.InvalidWireTypeException {
        int iB;
        this.k.getClass();
        InterfaceC1208u interfaceC1208uA = C1211x.a(j, obj);
        int i = c1197i.b;
        if ((i & 7) != 3) {
            throw InvalidProtocolBufferException.b();
        }
        do {
            AbstractC1206s abstractC1206sD = o2.d();
            c1197i.b(abstractC1206sD, o2, c1200l);
            o2.b(abstractC1206sD);
            ((M) interfaceC1208uA).add(abstractC1206sD);
            AbstractC1047f0 abstractC1047f0 = c1197i.a;
            if (abstractC1047f0.c() || c1197i.d != 0) {
                return;
            } else {
                iB = abstractC1047f0.B();
            }
        } while (iB == i);
        c1197i.d = iB;
    }

    public final void D(Object obj, int i, C1197i c1197i, O o2, C1200l c1200l) throws InvalidProtocolBufferException {
        int iB;
        this.k.getClass();
        InterfaceC1208u interfaceC1208uA = C1211x.a(i & 1048575, obj);
        int i2 = c1197i.b;
        if ((i2 & 7) != 2) {
            throw InvalidProtocolBufferException.b();
        }
        do {
            AbstractC1206s abstractC1206sD = o2.d();
            c1197i.c(abstractC1206sD, o2, c1200l);
            o2.b(abstractC1206sD);
            ((M) interfaceC1208uA).add(abstractC1206sD);
            AbstractC1047f0 abstractC1047f0 = c1197i.a;
            if (abstractC1047f0.c() || c1197i.d != 0) {
                return;
            } else {
                iB = abstractC1047f0.B();
            }
        } while (iB == i2);
        c1197i.d = iB;
    }

    public final void E(int i, C1197i c1197i, Object obj) throws InvalidProtocolBufferException.InvalidWireTypeException {
        if ((536870912 & i) != 0) {
            c1197i.v(2);
            Y.o(i & 1048575, obj, c1197i.a.A());
        } else if (!this.f) {
            Y.o(i & 1048575, obj, c1197i.e());
        } else {
            c1197i.v(2);
            Y.o(i & 1048575, obj, c1197i.a.z());
        }
    }

    public final void F(int i, C1197i c1197i, Object obj) throws InvalidProtocolBufferException.InvalidWireTypeException {
        boolean z = (536870912 & i) != 0;
        C1211x c1211x = this.k;
        if (z) {
            c1211x.getClass();
            c1197i.r(C1211x.a(i & 1048575, obj), true);
        } else {
            c1211x.getClass();
            c1197i.r(C1211x.a(i & 1048575, obj), false);
        }
    }

    public final void H(int i, Object obj) {
        int i2 = this.a[i + 2];
        long j = 1048575 & i2;
        if (j == 1048575) {
            return;
        }
        Y.m(j, obj, (1 << (i2 >>> 20)) | Y.c.f(j, obj));
    }

    public final void I(int i, int i2, Object obj) {
        Y.m(this.a[i2 + 2] & 1048575, obj, i);
    }

    public final void J(Object obj, int i, AbstractC1189a abstractC1189a) {
        o.putObject(obj, M(i) & 1048575, abstractC1189a);
        H(i, obj);
    }

    public final void K(Object obj, int i, int i2, AbstractC1189a abstractC1189a) {
        o.putObject(obj, M(i2) & 1048575, abstractC1189a);
        I(i, i2, obj);
    }

    public final int M(int i) {
        return this.a[i + 1];
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r15v1, types: [boolean] */
    /* JADX WARN: Type inference failed for: r15v10 */
    /* JADX WARN: Type inference failed for: r15v15 */
    /* JADX WARN: Type inference failed for: r15v16 */
    /* JADX WARN: Type inference failed for: r15v17 */
    /* JADX WARN: Type inference failed for: r15v18 */
    /* JADX WARN: Type inference failed for: r15v19 */
    /* JADX WARN: Type inference failed for: r15v2 */
    /* JADX WARN: Type inference failed for: r15v20 */
    /* JADX WARN: Type inference failed for: r15v21 */
    /* JADX WARN: Type inference failed for: r15v22 */
    /* JADX WARN: Type inference failed for: r15v23 */
    /* JADX WARN: Type inference failed for: r15v24 */
    /* JADX WARN: Type inference failed for: r15v25 */
    /* JADX WARN: Type inference failed for: r15v26 */
    /* JADX WARN: Type inference failed for: r15v27 */
    /* JADX WARN: Type inference failed for: r15v28 */
    /* JADX WARN: Type inference failed for: r15v29 */
    /* JADX WARN: Type inference failed for: r15v3 */
    /* JADX WARN: Type inference failed for: r15v30 */
    /* JADX WARN: Type inference failed for: r15v31 */
    /* JADX WARN: Type inference failed for: r15v32 */
    /* JADX WARN: Type inference failed for: r15v33 */
    /* JADX WARN: Type inference failed for: r15v34 */
    /* JADX WARN: Type inference failed for: r15v35 */
    /* JADX WARN: Type inference failed for: r15v36 */
    /* JADX WARN: Type inference failed for: r15v37 */
    /* JADX WARN: Type inference failed for: r15v38 */
    /* JADX WARN: Type inference failed for: r15v39 */
    /* JADX WARN: Type inference failed for: r15v4 */
    /* JADX WARN: Type inference failed for: r15v40 */
    /* JADX WARN: Type inference failed for: r15v41 */
    /* JADX WARN: Type inference failed for: r15v9 */
    public final void N(Object obj, A a) throws IOException {
        int i;
        int i2;
        boolean z;
        G g = this;
        int i3 = 1;
        int[] iArr = g.a;
        int length = iArr.length;
        Unsafe unsafe = o;
        int i4 = 1048575;
        int i5 = 0;
        int i6 = 0;
        while (i5 < length) {
            int iM = g.M(i5);
            int i7 = iArr[i5];
            int iL = L(iM);
            if (iL <= 17) {
                int i8 = iArr[i5 + 2];
                int i9 = i8 & 1048575;
                if (i9 != i4) {
                    i6 = i9 == 1048575 ? 0 : unsafe.getInt(obj, i9);
                    i4 = i9;
                }
                i = iM;
                i2 = i3 << (i8 >>> 20);
            } else {
                i = iM;
                i2 = 0;
            }
            ?? r15 = i3;
            int[] iArr2 = iArr;
            long j = i & 1048575;
            switch (iL) {
                case 0:
                    if (g.o(obj, i5, i4, i6, i2)) {
                        double d = Y.c.d(j, obj);
                        C1198j c1198j = (C1198j) a.a;
                        c1198j.getClass();
                        c1198j.t(i7, Double.doubleToRawLongBits(d));
                    }
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 1:
                    r15 = r15;
                    if (g.o(obj, i5, i4, i6, i2)) {
                        float fE = Y.c.e(j, obj);
                        C1198j c1198j2 = (C1198j) a.a;
                        c1198j2.getClass();
                        c1198j2.r(i7, Float.floatToRawIntBits(fE));
                        r15 = r15;
                    }
                    g = this;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 2:
                    r15 = r15;
                    if (g.o(obj, i5, i4, i6, i2)) {
                        ((C1198j) a.a).C(i7, unsafe.getLong(obj, j));
                        r15 = r15;
                    }
                    g = this;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 3:
                    r15 = r15;
                    if (g.o(obj, i5, i4, i6, i2)) {
                        ((C1198j) a.a).C(i7, unsafe.getLong(obj, j));
                        r15 = r15;
                    }
                    g = this;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 4:
                    r15 = r15;
                    if (g.o(obj, i5, i4, i6, i2)) {
                        ((C1198j) a.a).v(i7, unsafe.getInt(obj, j));
                        r15 = r15;
                    }
                    g = this;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 5:
                    r15 = r15;
                    if (g.o(obj, i5, i4, i6, i2)) {
                        ((C1198j) a.a).t(i7, unsafe.getLong(obj, j));
                        r15 = r15;
                    }
                    g = this;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 6:
                    r15 = r15;
                    if (g.o(obj, i5, i4, i6, i2)) {
                        ((C1198j) a.a).r(i7, unsafe.getInt(obj, j));
                        r15 = r15;
                    }
                    g = this;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 7:
                    r15 = r15;
                    if (g.o(obj, i5, i4, i6, i2)) {
                        ((C1198j) a.a).p(i7, Y.c.c(j, obj));
                        r15 = r15;
                    }
                    g = this;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 8:
                    r15 = r15;
                    if (g.o(obj, i5, i4, i6, i2)) {
                        Object object = unsafe.getObject(obj, j);
                        if (object instanceof String) {
                            ((C1198j) a.a).y(i7, (String) object);
                            r15 = r15;
                        } else {
                            ((C1198j) a.a).q(i7, (C1194f) object);
                            r15 = r15;
                        }
                    }
                    g = this;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 9:
                    if (g.o(obj, i5, i4, i6, i2)) {
                        ((C1198j) a.a).x(i7, (AbstractC1189a) unsafe.getObject(obj, j), g.m(i5));
                    }
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 10:
                    r15 = r15;
                    if (g.o(obj, i5, i4, i6, i2)) {
                        ((C1198j) a.a).q(i7, (C1194f) unsafe.getObject(obj, j));
                        r15 = r15;
                    }
                    g = this;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 11:
                    r15 = r15;
                    if (g.o(obj, i5, i4, i6, i2)) {
                        ((C1198j) a.a).A(i7, unsafe.getInt(obj, j));
                        r15 = r15;
                    }
                    g = this;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 12:
                    r15 = r15;
                    if (g.o(obj, i5, i4, i6, i2)) {
                        ((C1198j) a.a).v(i7, unsafe.getInt(obj, j));
                        r15 = r15;
                    }
                    g = this;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 13:
                    r15 = r15;
                    if (g.o(obj, i5, i4, i6, i2)) {
                        ((C1198j) a.a).r(i7, unsafe.getInt(obj, j));
                        r15 = r15;
                    }
                    g = this;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 14:
                    r15 = r15;
                    if (g.o(obj, i5, i4, i6, i2)) {
                        ((C1198j) a.a).t(i7, unsafe.getLong(obj, j));
                        r15 = r15;
                    }
                    g = this;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 15:
                    if (g.o(obj, i5, i4, i6, i2)) {
                        int i10 = unsafe.getInt(obj, j);
                        r15 = 1;
                        ((C1198j) a.a).A(i7, (i10 >> 31) ^ (i10 << 1));
                    } else {
                        r15 = 1;
                    }
                    g = this;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 16:
                    if (g.o(obj, i5, i4, i6, i2)) {
                        long j2 = unsafe.getLong(obj, j);
                        ((C1198j) a.a).C(i7, (j2 << 1) ^ (j2 >> 63));
                    }
                    r15 = 1;
                    g = this;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 17:
                    if (g.o(obj, i5, i4, i6, i2)) {
                        a.a(i7, unsafe.getObject(obj, j), g.m(i5));
                    }
                    r15 = 1;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 18:
                    P.n(iArr2[i5], (List) unsafe.getObject(obj, j), a, false);
                    r15 = 1;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 19:
                    P.r(iArr2[i5], (List) unsafe.getObject(obj, j), a, false);
                    r15 = 1;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 20:
                    P.t(iArr2[i5], (List) unsafe.getObject(obj, j), a, false);
                    r15 = 1;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 21:
                    P.z(iArr2[i5], (List) unsafe.getObject(obj, j), a, false);
                    r15 = 1;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case EventType.WINDOW_STATE /* 22 */:
                    P.s(iArr2[i5], (List) unsafe.getObject(obj, j), a, false);
                    r15 = 1;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case EventType.AUDIO /* 23 */:
                    P.q(iArr2[i5], (List) unsafe.getObject(obj, j), a, false);
                    r15 = 1;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case EventType.VIDEO /* 24 */:
                    P.p(iArr2[i5], (List) unsafe.getObject(obj, j), a, false);
                    r15 = 1;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case EventType.SUBS /* 25 */:
                    P.m(iArr2[i5], (List) unsafe.getObject(obj, j), a, false);
                    r15 = 1;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case EventType.CDN /* 26 */:
                    int i11 = iArr2[i5];
                    List list = (List) unsafe.getObject(obj, j);
                    Class cls = P.a;
                    if (list != null && !list.isEmpty()) {
                        a.getClass();
                        for (int i12 = 0; i12 < list.size(); i12++) {
                            ((C1198j) a.a).y(i11, (String) list.get(i12));
                        }
                    }
                    r15 = 1;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                    break;
                case 27:
                    int i13 = iArr2[i5];
                    List list2 = (List) unsafe.getObject(obj, j);
                    O oM = g.m(i5);
                    Class cls2 = P.a;
                    if (list2 != null && !list2.isEmpty()) {
                        a.getClass();
                        for (int i14 = 0; i14 < list2.size(); i14++) {
                            ((C1198j) a.a).x(i13, (AbstractC1189a) list2.get(i14), oM);
                        }
                    }
                    r15 = 1;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                    break;
                case 28:
                    int i15 = iArr2[i5];
                    List list3 = (List) unsafe.getObject(obj, j);
                    Class cls3 = P.a;
                    if (list3 != null && !list3.isEmpty()) {
                        a.getClass();
                        for (int i16 = 0; i16 < list3.size(); i16++) {
                            ((C1198j) a.a).q(i15, (C1194f) list3.get(i16));
                        }
                    }
                    r15 = 1;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                    break;
                case 29:
                    z = false;
                    P.y(iArr2[i5], (List) unsafe.getObject(obj, j), a, false);
                    r15 = 1;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 30:
                    z = false;
                    P.o(iArr2[i5], (List) unsafe.getObject(obj, j), a, false);
                    r15 = 1;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 31:
                    z = false;
                    P.u(iArr2[i5], (List) unsafe.getObject(obj, j), a, false);
                    r15 = 1;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 32:
                    z = false;
                    P.v(iArr2[i5], (List) unsafe.getObject(obj, j), a, false);
                    r15 = 1;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 33:
                    z = false;
                    P.w(iArr2[i5], (List) unsafe.getObject(obj, j), a, false);
                    r15 = 1;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 34:
                    z = false;
                    P.x(iArr2[i5], (List) unsafe.getObject(obj, j), a, false);
                    r15 = 1;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 35:
                    P.n(iArr2[i5], (List) unsafe.getObject(obj, j), a, r15);
                    r15 = 1;
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 36:
                    P.r(iArr2[i5], (List) unsafe.getObject(obj, j), a, r15);
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 37:
                    P.t(iArr2[i5], (List) unsafe.getObject(obj, j), a, r15);
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 38:
                    P.z(iArr2[i5], (List) unsafe.getObject(obj, j), a, r15);
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 39:
                    P.s(iArr2[i5], (List) unsafe.getObject(obj, j), a, r15);
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case RequestError.NETWORK_FAILURE /* 40 */:
                    P.q(iArr2[i5], (List) unsafe.getObject(obj, j), a, r15);
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case RequestError.NO_DEV_KEY /* 41 */:
                    P.p(iArr2[i5], (List) unsafe.getObject(obj, j), a, r15);
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 42:
                    P.m(iArr2[i5], (List) unsafe.getObject(obj, j), a, r15);
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 43:
                    P.y(iArr2[i5], (List) unsafe.getObject(obj, j), a, r15);
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 44:
                    P.o(iArr2[i5], (List) unsafe.getObject(obj, j), a, r15);
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 45:
                    P.u(iArr2[i5], (List) unsafe.getObject(obj, j), a, r15);
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 46:
                    P.v(iArr2[i5], (List) unsafe.getObject(obj, j), a, r15);
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 47:
                    P.w(iArr2[i5], (List) unsafe.getObject(obj, j), a, r15);
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 48:
                    P.x(iArr2[i5], (List) unsafe.getObject(obj, j), a, r15);
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 49:
                    int i17 = iArr2[i5];
                    List list4 = (List) unsafe.getObject(obj, j);
                    O oM2 = g.m(i5);
                    Class cls4 = P.a;
                    if (list4 != null && !list4.isEmpty()) {
                        a.getClass();
                        for (int i18 = 0; i18 < list4.size(); i18 += r15 == true ? 1 : 0) {
                            a.a(i17, list4.get(i18), oM2);
                        }
                    }
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                    break;
                case RequestError.RESPONSE_CODE_FAILURE /* 50 */:
                    if (unsafe.getObject(obj, j) != null) {
                        Object obj2 = g.b[(i5 / 3) * 2];
                        g.m.getClass();
                        android.support.v4.media.session.a.A(obj2);
                        throw null;
                    }
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 51:
                    if (g.q(i7, i5, obj)) {
                        double dDoubleValue = ((Double) Y.c.h(j, obj)).doubleValue();
                        C1198j c1198j3 = (C1198j) a.a;
                        c1198j3.getClass();
                        c1198j3.t(i7, Double.doubleToRawLongBits(dDoubleValue));
                    }
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 52:
                    if (g.q(i7, i5, obj)) {
                        float fFloatValue = ((Float) Y.c.h(j, obj)).floatValue();
                        C1198j c1198j4 = (C1198j) a.a;
                        c1198j4.getClass();
                        c1198j4.r(i7, Float.floatToRawIntBits(fFloatValue));
                    }
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 53:
                    if (g.q(i7, i5, obj)) {
                        ((C1198j) a.a).C(i7, A(j, obj));
                    }
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 54:
                    if (g.q(i7, i5, obj)) {
                        ((C1198j) a.a).C(i7, A(j, obj));
                    }
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 55:
                    if (g.q(i7, i5, obj)) {
                        ((C1198j) a.a).v(i7, z(j, obj));
                    }
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 56:
                    if (g.q(i7, i5, obj)) {
                        ((C1198j) a.a).t(i7, A(j, obj));
                    }
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 57:
                    if (g.q(i7, i5, obj)) {
                        ((C1198j) a.a).r(i7, z(j, obj));
                    }
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 58:
                    if (g.q(i7, i5, obj)) {
                        ((C1198j) a.a).p(i7, ((Boolean) Y.c.h(j, obj)).booleanValue());
                    }
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 59:
                    if (g.q(i7, i5, obj)) {
                        Object object2 = unsafe.getObject(obj, j);
                        if (object2 instanceof String) {
                            ((C1198j) a.a).y(i7, (String) object2);
                        } else {
                            ((C1198j) a.a).q(i7, (C1194f) object2);
                        }
                    }
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 60:
                    if (g.q(i7, i5, obj)) {
                        ((C1198j) a.a).x(i7, (AbstractC1189a) unsafe.getObject(obj, j), g.m(i5));
                    }
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 61:
                    if (g.q(i7, i5, obj)) {
                        ((C1198j) a.a).q(i7, (C1194f) unsafe.getObject(obj, j));
                    }
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 62:
                    if (g.q(i7, i5, obj)) {
                        ((C1198j) a.a).A(i7, z(j, obj));
                    }
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 63:
                    if (g.q(i7, i5, obj)) {
                        ((C1198j) a.a).v(i7, z(j, obj));
                    }
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 64:
                    if (g.q(i7, i5, obj)) {
                        ((C1198j) a.a).r(i7, z(j, obj));
                    }
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 65:
                    if (g.q(i7, i5, obj)) {
                        ((C1198j) a.a).t(i7, A(j, obj));
                    }
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 66:
                    if (g.q(i7, i5, obj)) {
                        int iZ = z(j, obj);
                        ((C1198j) a.a).A(i7, (iZ >> 31) ^ (iZ << 1));
                    }
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 67:
                    if (g.q(i7, i5, obj)) {
                        long jA = A(j, obj);
                        ((C1198j) a.a).C(i7, (jA << (r15 == true ? 1L : 0L)) ^ (jA >> 63));
                    }
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                case 68:
                    if (g.q(i7, i5, obj)) {
                        a.a(i7, unsafe.getObject(obj, j), g.m(i5));
                    }
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
                default:
                    i5 += 3;
                    i3 = r15;
                    iArr = iArr2;
            }
        }
        ((T) g.l).getClass();
        ((AbstractC1206s) obj).unknownFields.d(a);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:11:0x0025  */
    @Override // androidx.glance.appwidget.protobuf.O
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(java.lang.Object r11, java.lang.Object r12) {
        /*
            Method dump skipped, instructions count: 662
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.appwidget.protobuf.G.a(java.lang.Object, java.lang.Object):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x0080  */
    @Override // androidx.glance.appwidget.protobuf.O
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
            boolean r0 = r10 instanceof androidx.glance.appwidget.protobuf.AbstractC1206s
            r1 = 0
            if (r0 == 0) goto L1b
            r0 = r10
            androidx.glance.appwidget.protobuf.s r0 = (androidx.glance.appwidget.protobuf.AbstractC1206s) r0
            r2 = 2147483647(0x7fffffff, float:NaN)
            r0.j(r2)
            r0.memoizedHashCode = r1
            r0.g()
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
            sun.misc.Unsafe r4 = androidx.glance.appwidget.protobuf.G.o
            java.lang.Object r7 = r4.getObject(r10, r5)
            if (r7 == 0) goto L93
            androidx.glance.appwidget.protobuf.C r8 = r9.m
            r8.getClass()
            r8 = r7
            androidx.glance.appwidget.protobuf.B r8 = (androidx.glance.appwidget.protobuf.B) r8
            r8.a = r1
            r4.putObject(r10, r5, r7)
            goto L93
        L54:
            androidx.glance.appwidget.protobuf.x r4 = r9.k
            r4.getClass()
            androidx.glance.appwidget.protobuf.X r4 = androidx.glance.appwidget.protobuf.Y.c
            java.lang.Object r4 = r4.h(r5, r10)
            androidx.glance.appwidget.protobuf.u r4 = (androidx.glance.appwidget.protobuf.InterfaceC1208u) r4
            androidx.glance.appwidget.protobuf.b r4 = (androidx.glance.appwidget.protobuf.AbstractC1190b) r4
            boolean r5 = r4.a
            if (r5 == 0) goto L93
            r4.a = r1
            goto L93
        L6a:
            r4 = r0[r3]
            boolean r4 = r9.q(r4, r3, r10)
            if (r4 == 0) goto L93
            androidx.glance.appwidget.protobuf.O r4 = r9.m(r3)
            sun.misc.Unsafe r7 = androidx.glance.appwidget.protobuf.G.o
            java.lang.Object r5 = r7.getObject(r10, r5)
            r4.b(r5)
            goto L93
        L80:
            boolean r4 = r9.n(r3, r10)
            if (r4 == 0) goto L93
            androidx.glance.appwidget.protobuf.O r4 = r9.m(r3)
            sun.misc.Unsafe r7 = androidx.glance.appwidget.protobuf.G.o
            java.lang.Object r5 = r7.getObject(r10, r5)
            r4.b(r5)
        L93:
            int r3 = r3 + 3
            goto L1f
        L96:
            androidx.glance.appwidget.protobuf.Q r0 = r9.l
            androidx.glance.appwidget.protobuf.T r0 = (androidx.glance.appwidget.protobuf.T) r0
            r0.getClass()
            androidx.glance.appwidget.protobuf.s r10 = (androidx.glance.appwidget.protobuf.AbstractC1206s) r10
            androidx.glance.appwidget.protobuf.S r10 = r10.unknownFields
            boolean r0 = r10.e
            if (r0 == 0) goto La7
            r10.e = r1
        La7:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.appwidget.protobuf.G.b(java.lang.Object):void");
    }

    @Override // androidx.glance.appwidget.protobuf.O
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
                        if (!m(i2).c(Y.c.h(iM & 1048575, obj))) {
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
                                if (!m(i2).c(Y.c.h(iM & 1048575, obj))) {
                                }
                            } else {
                                continue;
                            }
                        } else if (iL != 49) {
                            if (iL != 50) {
                                continue;
                            } else {
                                Object objH = Y.c.h(iM & 1048575, obj);
                                this.m.getClass();
                                if (!((B) objH).isEmpty()) {
                                    android.support.v4.media.session.a.A(this.b[(i2 / 3) * 2]);
                                    throw null;
                                }
                            }
                        }
                        i6++;
                        i4 = i;
                        i5 = i3;
                    }
                    List list = (List) Y.c.h(iM & 1048575, obj);
                    if (list.isEmpty()) {
                        continue;
                    } else {
                        O oM = m(i2);
                        for (int i13 = 0; i13 < list.size(); i13++) {
                            if (oM.c(list.get(i13))) {
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

    @Override // androidx.glance.appwidget.protobuf.O
    public final AbstractC1206s d() {
        this.j.getClass();
        return this.e.h();
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:150:0x03a5 A[PHI: r17
  0x03a5: PHI (r17v46 int) = 
  (r17v29 int)
  (r17v30 int)
  (r17v31 int)
  (r17v35 int)
  (r17v37 int)
  (r17v38 int)
  (r17v39 int)
  (r17v43 int)
  (r17v47 int)
 binds: [B:209:0x053c, B:205:0x0520, B:201:0x0504, B:184:0x0491, B:170:0x042c, B:166:0x0412, B:162:0x03f8, B:155:0x03c2, B:149:0x03a3] A[DONT_GENERATE, DONT_INLINE]] */
    @Override // androidx.glance.appwidget.protobuf.O
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int e(androidx.glance.appwidget.protobuf.AbstractC1206s r19) {
        /*
            Method dump skipped, instructions count: 1954
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.appwidget.protobuf.G.e(androidx.glance.appwidget.protobuf.s):int");
    }

    @Override // androidx.glance.appwidget.protobuf.O
    public final void f(Object obj, C1197i c1197i, C1200l c1200l) {
        c1200l.getClass();
        if (!p(obj)) {
            throw new IllegalArgumentException(androidx.compose.ui.node.B.e(obj, "Mutating immutable message: "));
        }
        r(this.l, obj, c1197i, c1200l);
    }

    /* JADX WARN: Removed duplicated region for block: B:42:0x00e1 A[PHI: r3
  0x00e1: PHI (r3v32 int) = (r3v10 int), (r3v33 int) binds: [B:83:0x0216, B:41:0x00df] A[DONT_GENERATE, DONT_INLINE]] */
    @Override // androidx.glance.appwidget.protobuf.O
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int g(androidx.glance.appwidget.protobuf.AbstractC1206s r12) {
        /*
            Method dump skipped, instructions count: 796
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.appwidget.protobuf.G.g(androidx.glance.appwidget.protobuf.s):int");
    }

    @Override // androidx.glance.appwidget.protobuf.O
    public final void h(Object obj, A a) throws IOException {
        a.getClass();
        N(obj, a);
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x003d  */
    @Override // androidx.glance.appwidget.protobuf.O
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean i(androidx.glance.appwidget.protobuf.AbstractC1206s r12, androidx.glance.appwidget.protobuf.AbstractC1206s r13) {
        /*
            Method dump skipped, instructions count: 666
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.appwidget.protobuf.G.i(androidx.glance.appwidget.protobuf.s, androidx.glance.appwidget.protobuf.s):boolean");
    }

    public final boolean j(AbstractC1206s abstractC1206s, AbstractC1206s abstractC1206s2, int i) {
        return n(i, abstractC1206s) == n(i, abstractC1206s2);
    }

    public final void k(int i, Object obj, Object obj2) {
        int i2 = this.a[i];
        if (Y.c.h(M(i) & 1048575, obj) == null) {
            return;
        }
        l(i);
    }

    public final void l(int i) {
        if (this.b[((i / 3) * 2) + 1] != null) {
            throw new ClassCastException();
        }
    }

    public final O m(int i) {
        int i2 = (i / 3) * 2;
        Object[] objArr = this.b;
        O o2 = (O) objArr[i2];
        if (o2 != null) {
            return o2;
        }
        O oA = L.c.a((Class) objArr[i2 + 1]);
        objArr[i2] = oA;
        return oA;
    }

    public final boolean n(int i, Object obj) {
        int i2 = this.a[i + 2];
        long j = i2 & 1048575;
        if (j == 1048575) {
            int iM = M(i);
            long j2 = iM & 1048575;
            switch (L(iM)) {
                case 0:
                    if (Double.doubleToRawLongBits(Y.c.d(j2, obj)) == 0) {
                        return false;
                    }
                    break;
                case 1:
                    if (Float.floatToRawIntBits(Y.c.e(j2, obj)) == 0) {
                        return false;
                    }
                    break;
                case 2:
                    if (Y.c.g(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 3:
                    if (Y.c.g(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 4:
                    if (Y.c.f(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 5:
                    if (Y.c.g(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 6:
                    if (Y.c.f(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 7:
                    return Y.c.c(j2, obj);
                case 8:
                    Object objH = Y.c.h(j2, obj);
                    if (objH instanceof String) {
                        return !((String) objH).isEmpty();
                    }
                    if (objH instanceof C1194f) {
                        return !C1194f.c.equals(objH);
                    }
                    throw new IllegalArgumentException();
                case 9:
                    if (Y.c.h(j2, obj) == null) {
                        return false;
                    }
                    break;
                case 10:
                    return !C1194f.c.equals(Y.c.h(j2, obj));
                case 11:
                    if (Y.c.f(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 12:
                    if (Y.c.f(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 13:
                    if (Y.c.f(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 14:
                    if (Y.c.g(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 15:
                    if (Y.c.f(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 16:
                    if (Y.c.g(j2, obj) == 0) {
                        return false;
                    }
                    break;
                case 17:
                    if (Y.c.h(j2, obj) == null) {
                        return false;
                    }
                    break;
                default:
                    throw new IllegalArgumentException();
            }
        } else if (((1 << (i2 >>> 20)) & Y.c.f(j, obj)) == 0) {
            return false;
        }
        return true;
    }

    public final boolean o(Object obj, int i, int i2, int i3, int i4) {
        return i2 == 1048575 ? n(i, obj) : (i3 & i4) != 0;
    }

    public final boolean q(int i, int i2, Object obj) {
        return Y.c.f((long) (this.a[i2 + 2] & 1048575), obj) == i;
    }

    /*  JADX ERROR: Type inference failed
        jadx.core.utils.exceptions.JadxOverflowException: Type inference error: updates count limit reached
        	at jadx.core.utils.ErrorsCounter.addError(ErrorsCounter.java:59)
        	at jadx.core.utils.ErrorsCounter.error(ErrorsCounter.java:31)
        	at jadx.core.dex.attributes.nodes.NotificationAttrNode.addError(NotificationAttrNode.java:19)
        	at jadx.core.dex.visitors.typeinference.TypeInferenceVisitor.visit(TypeInferenceVisitor.java:77)
        */
    public final void r(androidx.glance.appwidget.protobuf.Q r21, java.lang.Object r22, androidx.glance.appwidget.protobuf.C1197i r23, androidx.glance.appwidget.protobuf.C1200l r24) {
        /*
            Method dump skipped, instructions count: 1896
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.appwidget.protobuf.G.r(androidx.glance.appwidget.protobuf.Q, java.lang.Object, androidx.glance.appwidget.protobuf.i, androidx.glance.appwidget.protobuf.l):void");
    }

    public final void s(int i, Object obj, Object obj2) {
        long jM = M(i) & 1048575;
        Object objH = Y.c.h(jM, obj);
        C c = this.m;
        if (objH != null) {
            c.getClass();
            if (!((B) objH).a) {
                B bE = B.b.e();
                C.a(bE, objH);
                Y.o(jM, obj, bE);
                objH = bE;
            }
        } else {
            c.getClass();
            objH = B.b.e();
            Y.o(jM, obj, objH);
        }
        c.getClass();
        android.support.v4.media.session.a.A(obj2);
        throw null;
    }

    public final void t(int i, Object obj, Object obj2) {
        if (n(i, obj2)) {
            long jM = M(i) & 1048575;
            Unsafe unsafe = o;
            Object object = unsafe.getObject(obj2, jM);
            if (object == null) {
                throw new IllegalStateException("Source subfield " + this.a[i] + " is present but null: " + obj2);
            }
            O oM = m(i);
            if (!n(i, obj)) {
                if (p(object)) {
                    AbstractC1206s abstractC1206sD = oM.d();
                    oM.a(abstractC1206sD, object);
                    unsafe.putObject(obj, jM, abstractC1206sD);
                } else {
                    unsafe.putObject(obj, jM, object);
                }
                H(i, obj);
                return;
            }
            Object object2 = unsafe.getObject(obj, jM);
            if (!p(object2)) {
                AbstractC1206s abstractC1206sD2 = oM.d();
                oM.a(abstractC1206sD2, object2);
                unsafe.putObject(obj, jM, abstractC1206sD2);
                object2 = abstractC1206sD2;
            }
            oM.a(object2, object);
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
            O oM = m(i);
            if (!q(i2, i, obj)) {
                if (p(object)) {
                    AbstractC1206s abstractC1206sD = oM.d();
                    oM.a(abstractC1206sD, object);
                    unsafe.putObject(obj, jM, abstractC1206sD);
                } else {
                    unsafe.putObject(obj, jM, object);
                }
                I(i2, i, obj);
                return;
            }
            Object object2 = unsafe.getObject(obj, jM);
            if (!p(object2)) {
                AbstractC1206s abstractC1206sD2 = oM.d();
                oM.a(abstractC1206sD2, object2);
                unsafe.putObject(obj, jM, abstractC1206sD2);
                object2 = abstractC1206sD2;
            }
            oM.a(object2, object);
        }
    }

    public final Object v(int i, Object obj) {
        O oM = m(i);
        long jM = M(i) & 1048575;
        if (!n(i, obj)) {
            return oM.d();
        }
        Object object = o.getObject(obj, jM);
        if (p(object)) {
            return object;
        }
        AbstractC1206s abstractC1206sD = oM.d();
        if (object != null) {
            oM.a(abstractC1206sD, object);
        }
        return abstractC1206sD;
    }

    public final Object w(int i, int i2, Object obj) {
        O oM = m(i2);
        if (!q(i, i2, obj)) {
            return oM.d();
        }
        Object object = o.getObject(obj, M(i2) & 1048575);
        if (p(object)) {
            return object;
        }
        AbstractC1206s abstractC1206sD = oM.d();
        if (object != null) {
            oM.a(abstractC1206sD, object);
        }
        return abstractC1206sD;
    }
}
