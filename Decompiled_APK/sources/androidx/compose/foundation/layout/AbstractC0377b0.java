package androidx.compose.foundation.layout;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.collection.AbstractC0214l;
import androidx.collection.C0212j;
import androidx.collection.C0222u;
import androidx.collection.C0223v;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.layout.C0900v;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.comscore.streaming.ContentType;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.layout.b0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0377b0 {
    public static final M a = new M(androidx.compose.ui.b.j);
    public static final L b = new L(androidx.compose.ui.b.m);

    public static final void a(androidx.compose.ui.q qVar, C0384f c0384f, C0380d c0380d, int i, int i2, I i3, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i4) {
        androidx.compose.runtime.internal.d dVar2;
        Object obj;
        int i5;
        C0380d c0380d2;
        I i6;
        C0384f c0384f2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1704849416);
        if (((i4 | (c0814p.f(qVar) ? 4 : 2) | 221616) & 599187) == 599186 && c0814p.x()) {
            c0814p.Q();
            c0384f2 = c0384f;
            c0380d2 = c0380d;
            i5 = i2;
            i6 = i3;
            dVar2 = dVar;
        } else {
            C0384f c0384f3 = AbstractC0398m.c;
            C0380d c0380d3 = AbstractC0398m.a;
            I i7 = I.i;
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            Object obj2 = objI;
            if (objI == v) {
                C0381d0 c0381d0 = new C0381d0();
                c0381d0.a = -1;
                c0814p.i0(c0381d0);
                obj2 = c0381d0;
            }
            C0381d0 c0381d02 = (C0381d0) obj2;
            boolean zF = c0814p.f(c0381d02);
            Object objI2 = c0814p.I();
            if (zF || objI2 == v) {
                float f = 0;
                C0395k0 c0395k0 = new C0395k0(false, c0380d3, c0384f3, f, b, f, i, c0381d02);
                c0814p.i0(c0395k0);
                objI2 = c0395k0;
            }
            C0395k0 c0395k02 = (C0395k0) objI2;
            Object objI3 = c0814p.I();
            if (objI3 == v) {
                ArrayList arrayList = new ArrayList();
                dVar2 = dVar;
                arrayList.add(new androidx.compose.runtime.internal.d(true, 985886665, new W(dVar2, 0, (byte) 0)));
                AbstractC0147y.k(2);
                c0814p.i0(arrayList);
                obj = arrayList;
            } else {
                dVar2 = dVar;
                obj = objI3;
            }
            androidx.compose.runtime.internal.d dVar3 = new androidx.compose.runtime.internal.d(true, -1953651383, new C0900v((List) obj, 0));
            boolean zF2 = c0814p.f(c0395k02);
            Object objI4 = c0814p.I();
            if (zF2 || objI4 == v) {
                objI4 = new androidx.compose.ui.layout.O(c0395k02);
                c0814p.i0(objI4);
            }
            androidx.compose.ui.layout.K k = (androidx.compose.ui.layout.K) objI4;
            int i8 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, k, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i8))) {
                android.support.v4.media.session.a.z(i8, c0814p, i8, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.animation.d0.w(0, dVar3, c0814p, true);
            i5 = Integer.MAX_VALUE;
            c0380d2 = c0380d3;
            i6 = i7;
            c0384f2 = c0384f3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new V(qVar, c0384f2, c0380d2, i, i5, i6, dVar2, i4);
        }
    }

    public static final void b(androidx.compose.ui.q qVar, InterfaceC0388h interfaceC0388h, InterfaceC0394k interfaceC0394k, int i, int i2, I i3, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i4, int i5) {
        int i6;
        int i7;
        androidx.compose.runtime.internal.d dVar2;
        Object obj;
        int i8;
        I i9;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(437853230);
        int i10 = i4 | (c0814p.f(qVar) ? 4 : 2);
        if ((i4 & 48) == 0) {
            i10 |= c0814p.f(interfaceC0388h) ? 32 : 16;
        }
        int i11 = i10 | (c0814p.f(interfaceC0394k) ? 256 : 128);
        int i12 = i5 & 8;
        if (i12 != 0) {
            i7 = i11 | 3072;
            i6 = i;
        } else {
            i6 = i;
            i7 = i11 | (c0814p.d(i6) ? 2048 : 1024);
        }
        int i13 = i7 | 221184;
        if ((599187 & i13) == 599186 && c0814p.x()) {
            c0814p.Q();
            i8 = i2;
            i9 = i3;
            dVar2 = dVar;
        } else {
            if (i12 != 0) {
                i6 = Integer.MAX_VALUE;
            }
            I i14 = I.j;
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            Object obj2 = objI;
            if (objI == v) {
                C0381d0 c0381d0 = new C0381d0();
                c0381d0.a = -1;
                c0814p.i0(c0381d0);
                obj2 = c0381d0;
            }
            C0381d0 c0381d02 = (C0381d0) obj2;
            int i15 = i13 >> 3;
            boolean zF = ((((i15 & 896) ^ 384) > 256 && c0814p.d(i6)) || (i15 & 384) == 256) | ((((i15 & 14) ^ 6) > 4 && c0814p.f(interfaceC0388h)) || (i15 & 6) == 4) | ((((i15 & ContentType.LONG_FORM_ON_DEMAND) ^ 48) > 32 && c0814p.f(interfaceC0394k)) || (i15 & 48) == 32) | c0814p.f(c0381d02);
            Object objI2 = c0814p.I();
            if (zF || objI2 == v) {
                C0395k0 c0395k0 = new C0395k0(true, interfaceC0388h, interfaceC0394k, interfaceC0388h.a(), a, interfaceC0394k.a(), i6, c0381d02);
                c0814p.i0(c0395k0);
                objI2 = c0395k0;
            }
            C0395k0 c0395k02 = (C0395k0) objI2;
            Object objI3 = c0814p.I();
            if (objI3 == v) {
                ArrayList arrayList = new ArrayList();
                dVar2 = dVar;
                arrayList.add(new androidx.compose.runtime.internal.d(true, -139531073, new W(dVar2, 1, (byte) 0)));
                AbstractC0147y.k(2);
                c0814p.i0(arrayList);
                obj = arrayList;
            } else {
                dVar2 = dVar;
                obj = objI3;
            }
            androidx.compose.runtime.internal.d dVar3 = new androidx.compose.runtime.internal.d(true, -1953651383, new C0900v((List) obj, 0));
            boolean zF2 = c0814p.f(c0395k02);
            Object objI4 = c0814p.I();
            if (zF2 || objI4 == v) {
                objI4 = new androidx.compose.ui.layout.O(c0395k02);
                c0814p.i0(objI4);
            }
            androidx.compose.ui.layout.K k = (androidx.compose.ui.layout.K) objI4;
            int i16 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, k, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i16))) {
                android.support.v4.media.session.a.z(i16, c0814p, i16, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.animation.d0.w(0, dVar3, c0814p, true);
            i8 = Integer.MAX_VALUE;
            i9 = i14;
        }
        int i17 = i6;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new X(qVar, interfaceC0388h, interfaceC0394k, i17, i8, i9, dVar2, i4, i5);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final androidx.compose.ui.layout.L c(androidx.compose.ui.layout.M m, InterfaceC0387g0 interfaceC0387g0, Iterator it2, float f, float f2, long j, int i, C0381d0 c0381d0) throws Throwable {
        int i2;
        kotlin.jvm.internal.J j2;
        C0212j c0212j;
        long j3;
        long j4;
        C0222u c0222u;
        C0222u c0222u2;
        ArrayList arrayList;
        androidx.compose.ui.layout.J j5;
        androidx.camera.camera2.internal.compat.workaround.a aVar;
        int i3;
        kotlin.jvm.internal.J j6;
        T tA;
        int i4;
        int i5;
        int iC;
        androidx.compose.ui.layout.M m2;
        int iB;
        int width;
        int i6;
        C0212j c0212j2;
        androidx.camera.camera2.internal.compat.workaround.a aVar2;
        int i7;
        int iMin;
        C0222u c0222u3;
        C0222u c0222u4;
        Integer numValueOf;
        int i8;
        int i9;
        androidx.compose.ui.layout.M m3 = m;
        InterfaceC0387g0 interfaceC0387g02 = interfaceC0387g0;
        Iterator it3 = it2;
        androidx.compose.runtime.collection.b bVar = new androidx.compose.runtime.collection.b(new androidx.compose.ui.layout.L[16]);
        int iH = androidx.compose.ui.unit.a.h(j);
        int iJ = androidx.compose.ui.unit.a.j(j);
        int iG = androidx.compose.ui.unit.a.g(j);
        C0223v c0223v = AbstractC0214l.a;
        C0223v c0223v2 = new C0223v();
        ArrayList arrayList2 = new ArrayList();
        int iCeil = (int) Math.ceil(m3.c0(f));
        int iCeil2 = (int) Math.ceil(m3.c0(f2));
        long jA = L5.a(0, iH, 0, iG);
        long jZ = AbstractC0382e.z(interfaceC0387g02.i() ? 1 : 2, AbstractC0382e.m(14, jA));
        kotlin.jvm.internal.J j7 = new kotlin.jvm.internal.J();
        C0383e0 c0383e0 = it3 instanceof F ? new C0383e0(m3.O(iH), m3.O(iG)) : null;
        androidx.compose.ui.layout.J jF = !it3.hasNext() ? null : f(it3, c0383e0);
        if (jF != null) {
            i2 = iCeil;
            j2 = j7;
            c0212j = new C0212j(e(jF, interfaceC0387g02, jZ, new Y(j7, 1)));
        } else {
            i2 = iCeil;
            j2 = j7;
            c0212j = null;
        }
        Integer numValueOf2 = c0212j != null ? Integer.valueOf((int) (c0212j.a >> 32)) : null;
        Integer numValueOf3 = c0212j != null ? Integer.valueOf((int) (c0212j.a & 4294967295L)) : null;
        C0222u c0222u5 = new C0222u();
        C0222u c0222u6 = new C0222u();
        U u = new U(i, c0381d0, j, i2, iCeil2);
        C0212j c0212j3 = c0212j;
        androidx.camera.camera2.internal.compat.workaround.a aVarB = u.b(it3.hasNext(), 0, C0212j.a(iH, iG), c0212j3, 0, 0, 0, false, false);
        if (aVarB.b) {
            aVar = aVarB;
            j5 = jF;
            j3 = jA;
            j4 = jZ;
            c0222u2 = c0222u6;
            c0222u = c0222u5;
            arrayList = arrayList2;
            i3 = iG;
            j6 = j2;
            tA = u.a(aVar, c0212j3 != null, -1, 0, iH, 0);
        } else {
            j3 = jA;
            j4 = jZ;
            c0222u = c0222u5;
            c0222u2 = c0222u6;
            arrayList = arrayList2;
            j5 = jF;
            aVar = aVarB;
            i3 = iG;
            j6 = j2;
            tA = null;
        }
        int i10 = iH;
        int i11 = i3;
        androidx.compose.ui.layout.J j8 = j5;
        int i12 = iJ;
        int i13 = 0;
        int i14 = 0;
        int i15 = 0;
        int i16 = 0;
        int i17 = 0;
        T t = tA;
        androidx.camera.camera2.internal.compat.workaround.a aVar3 = aVar;
        int i18 = 0;
        while (!aVar3.b && j8 != null) {
            Intrinsics.d(numValueOf2);
            int iIntValue = numValueOf2.intValue();
            Intrinsics.d(numValueOf3);
            int i19 = iH;
            int i20 = i14 + iIntValue;
            int iMax = Math.max(i18, numValueOf3.intValue());
            int i21 = i10 - iIntValue;
            int i22 = i13 + 1;
            int i23 = i12;
            c0381d0.a = i22;
            arrayList.add(j8);
            c0223v2.h(i13, j6.a);
            int i24 = i22 - i15;
            boolean z = i24 < i;
            if (c0383e0 != null) {
                int i25 = z ? i16 : i16 + 1;
                if (z) {
                    int i26 = i21 - i2;
                    if (i26 < 0) {
                        i26 = 0;
                    }
                    int i27 = i26;
                    i6 = i24;
                    i8 = i27;
                } else {
                    i6 = i24;
                    i8 = i19;
                }
                m3.O(i8);
                if (z) {
                    i9 = i11;
                } else {
                    i9 = (i11 - iMax) - iCeil2;
                    if (i9 < 0) {
                        i9 = 0;
                    }
                }
                m3.O(i9);
                c0383e0.a = i25;
            } else {
                i6 = i24;
            }
            androidx.compose.ui.layout.J jF2 = !it3.hasNext() ? null : f(it3, c0383e0);
            j6.a = null;
            C0212j c0212j4 = jF2 != null ? new C0212j(e(jF2, interfaceC0387g02, j4, new Y(j6, 0))) : null;
            Integer numValueOf4 = c0212j4 != null ? Integer.valueOf(((int) (c0212j4.a >> 32)) + i2) : null;
            numValueOf3 = c0212j4 != null ? Integer.valueOf((int) (c0212j4.a & 4294967295L)) : null;
            boolean zHasNext = it2.hasNext();
            int i28 = i16;
            long jA2 = C0212j.a(i21, i11);
            if (c0212j4 == null) {
                c0212j2 = null;
            } else {
                Intrinsics.d(numValueOf4);
                int iIntValue2 = numValueOf4.intValue();
                Intrinsics.d(numValueOf3);
                c0212j2 = new C0212j(C0212j.a(iIntValue2, numValueOf3.intValue()));
            }
            androidx.camera.camera2.internal.compat.workaround.a aVarB2 = u.b(zHasNext, i6, jA2, c0212j2, i28, i17, iMax, false, false);
            int i29 = iMax;
            if (aVarB2.a) {
                iMin = Math.min(Math.max(i23, i20), i19);
                int i30 = i17 + i29;
                aVar2 = aVarB2;
                T tA2 = u.a(aVar2, c0212j4 != null, i28, i30, i21, i6);
                c0222u4 = c0222u2;
                c0222u4.a(i29);
                int i31 = (i3 - i30) - iCeil2;
                c0222u3 = c0222u;
                c0222u3.a(i22);
                numValueOf = numValueOf4 != null ? Integer.valueOf(numValueOf4.intValue() - i2) : null;
                i16 = i28 + 1;
                t = tA2;
                i7 = i19;
                i19 = i7;
                i15 = i22;
                i17 = i30 + iCeil2;
                i14 = 0;
                i11 = i31;
                i29 = 0;
            } else {
                aVar2 = aVarB2;
                i7 = i21;
                iMin = i23;
                c0222u3 = c0222u;
                c0222u4 = c0222u2;
                i14 = i20;
                i16 = i28;
                numValueOf = numValueOf4;
            }
            int i32 = i19;
            numValueOf2 = numValueOf;
            iH = i32;
            interfaceC0387g02 = interfaceC0387g0;
            j8 = jF2;
            c0222u2 = c0222u4;
            c0222u = c0222u3;
            i13 = i22;
            aVar3 = aVar2;
            i10 = i7;
            i18 = i29;
            i12 = iMin;
            m3 = m;
            it3 = it2;
        }
        int i33 = i12;
        C0222u c0222u7 = c0222u;
        C0222u c0222u8 = c0222u2;
        if (t != null) {
            T t2 = t;
            arrayList.add((androidx.compose.ui.layout.J) t2.c);
            c0223v2.h(arrayList.size() - 1, (androidx.compose.ui.layout.W) t2.d);
            int i34 = c0222u7.b - 1;
            boolean z2 = t2.a;
            long j9 = t2.b;
            if (z2) {
                c0222u8.g(i34, Math.max(c0222u8.c(i34), (int) (j9 & 4294967295L)));
                c0222u7.g(i34, c0222u7.d() + 1);
            } else {
                c0222u8.a((int) (j9 & 4294967295L));
                c0222u7.a(c0222u7.d() + 1);
            }
        }
        int size = arrayList.size();
        androidx.compose.ui.layout.W[] wArr = new androidx.compose.ui.layout.W[size];
        for (int i35 = 0; i35 < size; i35++) {
            wArr[i35] = c0223v2.e(i35);
        }
        int i36 = c0222u7.b;
        int[] iArr = new int[i36];
        for (int i37 = 0; i37 < i36; i37++) {
            iArr[i37] = 0;
        }
        int i38 = 0;
        int i39 = c0222u7.b;
        int[] iArr2 = new int[i39];
        int i40 = 0;
        while (i40 < i39) {
            iArr2[i40] = i38;
            i40++;
            i38 = 0;
        }
        int[] iArr3 = c0222u7.a;
        int i41 = c0222u7.b;
        int iMax2 = i33;
        int i42 = 0;
        int i43 = 0;
        int i44 = 0;
        while (i43 < i41) {
            int i45 = iArr3[i43];
            ArrayList arrayList3 = arrayList;
            C0222u c0222u9 = c0222u8;
            androidx.compose.ui.layout.L lQ = AbstractC0382e.q(interfaceC0387g0, iMax2, androidx.compose.ui.unit.a.i(j3), androidx.compose.ui.unit.a.h(j3), c0222u8.c(i43), i2, m, arrayList3, wArr, i42, i45, iArr, i43);
            if (interfaceC0387g0.i()) {
                iB = lQ.getWidth();
                width = lQ.b();
            } else {
                iB = lQ.b();
                width = lQ.getWidth();
            }
            iArr2[i43] = width;
            i44 += width;
            iMax2 = Math.max(iMax2, iB);
            bVar.b(lQ);
            i43++;
            arrayList = arrayList3;
            i42 = i45;
            c0222u8 = c0222u9;
        }
        if (bVar.l()) {
            i5 = 0;
            i4 = 0;
        } else {
            i4 = iMax2;
            i5 = i44;
        }
        boolean zI = interfaceC0387g0.i();
        InterfaceC0394k interfaceC0394kH = interfaceC0387g0.h();
        InterfaceC0388h interfaceC0388hG = interfaceC0387g0.g();
        if (zI) {
            if (interfaceC0394kH == null) {
                throw new IllegalArgumentException("null verticalArrangement");
            }
            int iC2 = kotlin.ranges.l.c(androidx.compose.animation.d0.c(bVar.c, 1, m.m0(interfaceC0394kH.a()), i5), androidx.compose.ui.unit.a.i(j), androidx.compose.ui.unit.a.g(j));
            interfaceC0394kH.b(m, iC2, iArr2, iArr);
            iC = iC2;
            m2 = m;
        } else {
            if (interfaceC0388hG == null) {
                throw new IllegalArgumentException("null horizontalArrangement");
            }
            iC = kotlin.ranges.l.c(androidx.compose.animation.d0.c(bVar.c, 1, m.m0(interfaceC0388hG.a()), i5), androidx.compose.ui.unit.a.i(j), androidx.compose.ui.unit.a.g(j));
            m2 = m;
            interfaceC0388hG.c(m2, iC, iArr2, m.getLayoutDirection(), iArr);
        }
        int iC3 = kotlin.ranges.l.c(i4, androidx.compose.ui.unit.a.j(j), androidx.compose.ui.unit.a.h(j));
        if (zI) {
            int i46 = iC;
            iC = iC3;
            iC3 = i46;
        }
        return m2.n0(iC, iC3, kotlin.collections.V.c(), new C0375a0(0, bVar));
    }

    public static final long d(List list, kotlin.jvm.functions.c cVar, kotlin.jvm.functions.c cVar2, int i, int i2, int i3, int i4, C0381d0 c0381d0) {
        boolean z;
        U u;
        C0212j c0212j;
        int i5 = 0;
        if (list.isEmpty()) {
            return C0212j.a(0, 0);
        }
        int i6 = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        U u2 = new U(i4, c0381d0, L5.a(0, i, 0, SubsamplingScaleImageView.TILE_SIZE_AUTO), i2, i3);
        androidx.compose.ui.layout.J j = (androidx.compose.ui.layout.J) CollectionsKt.O(0, list);
        int iIntValue = j != null ? ((Number) cVar2.invoke(j, 0, Integer.valueOf(i))).intValue() : 0;
        int iIntValue2 = j != null ? ((Number) cVar.invoke(j, 0, Integer.valueOf(iIntValue))).intValue() : 0;
        int i7 = 0;
        int iMax = 0;
        if (u2.b(list.size() > 1, 0, C0212j.a(i, SubsamplingScaleImageView.TILE_SIZE_AUTO), j == null ? null : new C0212j(C0212j.a(iIntValue2, iIntValue)), 0, 0, 0, false, false).b) {
            C0212j c0212jA = c0381d0.a(0, 0, j != null);
            return C0212j.a(c0212jA != null ? (int) (c0212jA.a & 4294967295L) : 0, 0);
        }
        int size = list.size();
        int i8 = i;
        int i9 = 0;
        int i10 = 0;
        int i11 = 0;
        int i12 = 0;
        while (true) {
            int i13 = iMax;
            if (i9 >= size) {
                break;
            }
            int i14 = i8 - iIntValue2;
            int i15 = i9 + 1;
            iMax = Math.max(i13, iIntValue);
            androidx.compose.ui.layout.J j2 = (androidx.compose.ui.layout.J) CollectionsKt.O(i15, list);
            int iIntValue3 = j2 != null ? ((Number) cVar2.invoke(j2, Integer.valueOf(i15), Integer.valueOf(i))).intValue() : i5;
            int iIntValue4 = j2 != null ? ((Number) cVar.invoke(j2, Integer.valueOf(i15), Integer.valueOf(iIntValue3))).intValue() + i2 : 0;
            if (i9 + 2 < list.size()) {
                i9 = i15;
                z = true;
            } else {
                i9 = i15;
                z = false;
            }
            int i16 = i9 - i11;
            int i17 = i12;
            long jA = C0212j.a(i14, i6);
            if (j2 == null) {
                u = u2;
                c0212j = null;
            } else {
                u = u2;
                c0212j = new C0212j(C0212j.a(iIntValue4, iIntValue3));
            }
            u2 = u;
            androidx.camera.camera2.internal.compat.workaround.a aVarB = u2.b(z, i16, jA, c0212j, i17, i7, iMax, false, false);
            if (aVarB.a) {
                int i18 = iMax + i3 + i7;
                T tA = u2.a(aVarB, j2 != null, i17, i18, i14, i16);
                iIntValue4 -= i2;
                i12 = i17 + 1;
                if (aVarB.b) {
                    if (tA != null && !tA.a) {
                        i18 = ((int) (tA.b & 4294967295L)) + i3 + i18;
                    }
                    i7 = i18;
                    i10 = i9;
                } else {
                    i8 = i;
                    i11 = i9;
                    i7 = i18;
                    iMax = 0;
                }
            } else {
                i8 = i14;
                i12 = i17;
            }
            iIntValue2 = iIntValue4;
            iIntValue = iIntValue3;
            i10 = i9;
            i6 = SubsamplingScaleImageView.TILE_SIZE_AUTO;
            i5 = 0;
        }
        return C0212j.a(i7 - i3, i10);
    }

    public static final long e(androidx.compose.ui.layout.J j, InterfaceC0387g0 interfaceC0387g0, long j2, Function1 function1) {
        if (AbstractC0382e.o(AbstractC0382e.n(j)) != DefinitionKt.NO_Float_VALUE) {
            int iX = interfaceC0387g0.i() ? j.x(SubsamplingScaleImageView.TILE_SIZE_AUTO) : j.X(SubsamplingScaleImageView.TILE_SIZE_AUTO);
            return C0212j.a(iX, interfaceC0387g0.i() ? j.X(iX) : j.x(iX));
        }
        AbstractC0382e.n(j);
        androidx.compose.ui.layout.W wB = j.B(j2);
        function1.invoke(wB);
        return C0212j.a(interfaceC0387g0.c(wB), interfaceC0387g0.e(wB));
    }

    public static final androidx.compose.ui.layout.J f(Iterator it2, C0383e0 c0383e0) {
        try {
            if (!(it2 instanceof F)) {
                return (androidx.compose.ui.layout.J) it2.next();
            }
            Intrinsics.d(c0383e0);
            return ((F) it2).a(c0383e0);
        } catch (IndexOutOfBoundsException unused) {
            return null;
        }
    }
}
