package androidx.compose.foundation.pager;

import androidx.camera.camera2.internal.p0;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.foundation.layout.A0;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.foundation.lazy.layout.AbstractC0448u;
import androidx.compose.foundation.lazy.layout.U;
import androidx.compose.foundation.lazy.layout.X;
import androidx.compose.material3.C0699p0;
import androidx.compose.material3.Z0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.H0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.layout.L;
import androidx.compose.ui.layout.f0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3200m0;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.List;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.collections.C4927s;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;

/* loaded from: classes.dex */
public final class w extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ float b;
    public final /* synthetic */ int c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ InterfaceC4938g g;
    public final /* synthetic */ Object h;
    public final /* synthetic */ Object i;
    public final /* synthetic */ Object j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public w(C0466e c0466e, A0 a0, float f, l lVar, kotlin.reflect.k kVar, Function0 function0, androidx.compose.ui.h hVar, int i, androidx.compose.foundation.gestures.snapping.n nVar, kotlinx.coroutines.C c) {
        super(2);
        this.d = c0466e;
        this.e = a0;
        this.b = f;
        this.f = lVar;
        this.g = kVar;
        this.h = function0;
        this.i = hVar;
        this.c = i;
        this.j = nVar;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v12, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r1v13 */
    /* JADX WARN: Type inference failed for: r1v15, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r1v16 */
    /* JADX WARN: Type inference failed for: r1v34, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r1v35, types: [kotlin.collections.K] */
    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        androidx.compose.ui.g gVar;
        int i;
        long j;
        int i2;
        androidx.compose.ui.h hVar;
        int i3;
        U u;
        androidx.compose.ui.h hVar2;
        long j2;
        int i4;
        int i5;
        int i6;
        C0472k c0472k;
        int i7;
        U u2;
        ArrayList arrayList;
        C0466e c0466e;
        C0472k c0472k2;
        int i8;
        boolean z;
        int i9;
        int i10;
        Object obj3;
        int i11;
        List list;
        ArrayList arrayList2;
        ?? arrayList3;
        ?? arrayList4;
        Object obj4;
        x xVar;
        InterfaceC4938g interfaceC4938g = this.g;
        Object obj5 = this.f;
        Object obj6 = this.e;
        Object obj7 = this.d;
        Object obj8 = this.i;
        Object obj9 = this.h;
        Object obj10 = this.j;
        switch (this.a) {
            case 0:
                U u3 = (U) obj;
                long j3 = ((androidx.compose.ui.unit.a) obj2).a;
                C0466e c0466e2 = (C0466e) obj7;
                c0466e2.C.getValue();
                EnumC0320d0 enumC0320d0 = EnumC0320d0.b;
                AbstractC0460p.i(j3, enumC0320d0);
                A0 a0 = (A0) obj6;
                int iM0 = u3.b.m0(AbstractC0382e.k(a0, u3.b.getLayoutDirection()));
                int iM02 = u3.b.m0(AbstractC0382e.j(a0, u3.b.getLayoutDirection()));
                int iM03 = u3.b.m0(a0.b);
                f0 f0Var = u3.b;
                int iM04 = f0Var.m0(a0.d) + iM03;
                int i12 = iM02 + iM0;
                int i13 = i12 - iM0;
                long jO = L5.o(-i12, -iM04, j3);
                c0466e2.p = u3;
                int iM05 = f0Var.m0(this.b);
                int iH = androidx.compose.ui.unit.a.h(j3) - i12;
                long jB = P5.b(iM0, iM03);
                ((l) obj5).getClass();
                int i14 = iH < 0 ? 0 : iH;
                c0466e2.z = L5.b(i14, androidx.compose.ui.unit.a.g(jO), 5);
                u uVar = (u) ((kotlin.reflect.k) interfaceC4938g).invoke();
                androidx.compose.foundation.gestures.snapping.n nVar = (androidx.compose.foundation.gestures.snapping.n) obj10;
                androidx.compose.runtime.snapshots.h hVarD = androidx.compose.runtime.snapshots.r.d();
                Function1 function1E = hVarD != null ? hVarD.e() : null;
                androidx.compose.runtime.snapshots.h hVarE = androidx.compose.runtime.snapshots.r.e(hVarD);
                try {
                    int iJ = c0466e2.j();
                    EnumC0320d0 enumC0320d02 = enumC0320d0;
                    p0 p0Var = c0466e2.c;
                    int iH2 = AbstractC0448u.h(uVar, p0Var.e, iJ);
                    if (iJ != iH2) {
                        ((H0) p0Var.d).j(iH2);
                        ((X) p0Var.f).a(iJ);
                    }
                    c0466e2.j();
                    float fJ = p0Var.j();
                    c0466e2.l();
                    nVar.getClass();
                    float f = 0;
                    int i15 = i14 + iM05;
                    int iB = kotlin.math.c.b(f - (i15 * fJ));
                    Unit unit = Unit.a;
                    androidx.compose.runtime.snapshots.r.g(hVarD, hVarE, function1E);
                    List listF = AbstractC0448u.f(uVar, c0466e2.A, c0466e2.v);
                    int iIntValue = ((Number) ((Function0) obj9).invoke()).intValue();
                    int i16 = i14;
                    int i17 = iH2;
                    androidx.compose.foundation.lazy.l lVar = new androidx.compose.foundation.lazy.l(u3, j3, i12, iM04, 2);
                    U u4 = u3;
                    if (iM0 < 0) {
                        throw new IllegalArgumentException("negative beforeContentPadding");
                    }
                    if (i13 < 0) {
                        throw new IllegalArgumentException("negative afterContentPadding");
                    }
                    int i18 = i15 < 0 ? 0 : i15;
                    int i19 = this.c;
                    androidx.compose.foundation.gestures.snapping.n nVar2 = (androidx.compose.foundation.gestures.snapping.n) obj10;
                    if (iIntValue <= 0) {
                        xVar = new x(kotlin.collections.K.a, i16, iM05, i13, -iM0, iH + i13, i19, nVar2, (L) lVar.invoke(Integer.valueOf(androidx.compose.ui.unit.a.j(jO)), Integer.valueOf(androidx.compose.ui.unit.a.i(jO)), C0465d.c));
                        c0466e = c0466e2;
                    } else {
                        int i20 = i16;
                        long jB2 = L5.b(i20, androidx.compose.ui.unit.a.g(jO), 5);
                        while (i17 > 0 && iB > 0) {
                            i17--;
                            iB -= i18;
                        }
                        int i21 = iB * (-1);
                        if (i17 >= iIntValue) {
                            i17 = iIntValue - 1;
                            i21 = 0;
                        }
                        C4927s c4927s = new C4927s();
                        u uVar2 = uVar;
                        int i22 = -iM0;
                        int i23 = i22 + (iM05 < 0 ? iM05 : 0);
                        int i24 = i21 + i23;
                        int i25 = i17;
                        int iMax = 0;
                        while (true) {
                            gVar = androidx.compose.ui.b.n;
                            i = i18;
                            j = jB;
                            i2 = i25;
                            hVar = (androidx.compose.ui.h) obj8;
                            if (i24 < 0 && i2 > 0) {
                                androidx.compose.foundation.lazy.l lVar2 = lVar;
                                int i26 = i2 - 1;
                                int i27 = i20;
                                long j4 = jB2;
                                u uVar3 = uVar2;
                                EnumC0320d0 enumC0320d03 = enumC0320d02;
                                List list2 = listF;
                                C0472k c0472kB = AbstractC3200m0.b(u4, i26, j4, uVar3, j, enumC0320d03, gVar, hVar, f0Var.getLayoutDirection(), false, i27);
                                c4927s.add(0, c0472kB);
                                iMax = Math.max(iMax, c0472kB.j);
                                i24 += i;
                                i20 = i27;
                                listF = list2;
                                enumC0320d02 = enumC0320d03;
                                uVar2 = uVar3;
                                jB2 = j4;
                                jB = j;
                                i18 = i;
                                i25 = i26;
                                lVar = lVar2;
                            }
                        }
                        androidx.compose.foundation.lazy.l lVar3 = lVar;
                        int i28 = i20;
                        long j5 = jB2;
                        u uVar4 = uVar2;
                        EnumC0320d0 enumC0320d04 = enumC0320d02;
                        List list3 = listF;
                        if (i24 < i23) {
                            i24 = i23;
                        }
                        int i29 = i24 - i23;
                        List list4 = list3;
                        int i30 = iH + i13;
                        int i31 = i30 < 0 ? 0 : i30;
                        androidx.compose.ui.g gVar2 = gVar;
                        int i32 = i29;
                        int i33 = -i29;
                        int i34 = iMax;
                        int i35 = i2;
                        int i36 = 0;
                        boolean z2 = false;
                        while (i36 < c4927s.c) {
                            if (i33 >= i31) {
                                c4927s.b(i36);
                                z2 = true;
                            } else {
                                i35++;
                                i33 += i;
                                i36++;
                            }
                        }
                        int i37 = i35;
                        int iMax2 = i34;
                        boolean z3 = z2;
                        int i38 = i2;
                        while (i37 < iIntValue && (i33 < i31 || i33 <= 0 || c4927s.isEmpty())) {
                            int i39 = i31;
                            int i40 = i37;
                            C0472k c0472kB2 = AbstractC3200m0.b(u4, i40, j5, uVar4, j, enumC0320d04, gVar2, hVar, f0Var.getLayoutDirection(), false, i28);
                            U u5 = u4;
                            int i41 = iIntValue - 1;
                            i33 += i40 == i41 ? i28 : i;
                            if (i33 > i23 || i40 == i41) {
                                iMax2 = Math.max(iMax2, c0472kB2.j);
                                c4927s.addLast(c0472kB2);
                            } else {
                                i32 -= i;
                                i38 = i40 + 1;
                                z3 = true;
                            }
                            i37 = i40 + 1;
                            u4 = u5;
                            i31 = i39;
                        }
                        int i42 = i37;
                        U u6 = u4;
                        if (i33 < iH) {
                            int i43 = iH - i33;
                            int i44 = i33 + i43;
                            i4 = i32 - i43;
                            while (i4 < iM0 && i38 > 0) {
                                int i45 = i38 - 1;
                                U u7 = u6;
                                int i46 = i44;
                                C0472k c0472kB3 = AbstractC3200m0.b(u7, i45, j5, uVar4, j, enumC0320d04, gVar2, hVar, f0Var.getLayoutDirection(), false, i28);
                                c4927s.add(0, c0472kB3);
                                iMax2 = Math.max(iMax2, c0472kB3.j);
                                i4 += i;
                                gVar2 = gVar2;
                                j5 = j5;
                                i38 = i45;
                                hVar = hVar;
                                i44 = i46;
                                i42 = i42;
                                u6 = u7;
                            }
                            int i47 = i44;
                            i3 = i42;
                            u = u6;
                            hVar2 = hVar;
                            j2 = j5;
                            if (i4 < 0) {
                                i33 = i47 + i4;
                                i4 = 0;
                            } else {
                                i33 = i47;
                            }
                        } else {
                            i3 = i42;
                            u = u6;
                            hVar2 = hVar;
                            j2 = j5;
                            i4 = i32;
                        }
                        if (i4 < 0) {
                            throw new IllegalArgumentException("invalid currentFirstPageScrollOffset");
                        }
                        int i48 = -i4;
                        C0472k c0472k3 = (C0472k) c4927s.first();
                        if (iM0 > 0 || iM05 < 0) {
                            int i49 = c4927s.c;
                            C0472k c0472k4 = c0472k3;
                            int i50 = i4;
                            int i51 = 0;
                            while (i51 < i49 && i50 != 0 && i <= i50) {
                                i5 = i;
                                if (i51 != kotlin.collections.B.i(c4927s)) {
                                    i50 -= i5;
                                    i51++;
                                    c0472k4 = (C0472k) c4927s.get(i51);
                                    i = i5;
                                } else {
                                    i6 = i50;
                                    c0472k = c0472k4;
                                }
                            }
                            i5 = i;
                            i6 = i50;
                            c0472k = c0472k4;
                        } else {
                            i5 = i;
                            i6 = i4;
                            c0472k = c0472k3;
                        }
                        int i52 = i48;
                        U u8 = u;
                        long j6 = j2;
                        androidx.compose.ui.h hVar3 = hVar2;
                        v vVar = new v(u8, j6, uVar4, j, hVar3, i28, 1);
                        U u9 = u8;
                        int i53 = i3;
                        int iMax3 = Math.max(0, i38 - i19);
                        int i54 = i38 - 1;
                        if (iMax3 <= i54) {
                            ArrayList arrayList5 = null;
                            while (true) {
                                if (arrayList5 == null) {
                                    arrayList5 = new ArrayList();
                                }
                                i7 = iMax2;
                                arrayList = arrayList5;
                                u2 = u9;
                                arrayList.add(vVar.invoke(Integer.valueOf(i54)));
                                if (i54 != iMax3) {
                                    i54--;
                                    u9 = u2;
                                    arrayList5 = arrayList;
                                    iMax2 = i7;
                                }
                            }
                        } else {
                            i7 = iMax2;
                            u2 = u9;
                            arrayList = null;
                        }
                        int size = list4.size();
                        List arrayList6 = arrayList;
                        int i55 = 0;
                        while (i55 < size) {
                            int i56 = size;
                            List list5 = list4;
                            int i57 = i55;
                            int iIntValue2 = ((Number) list5.get(i55)).intValue();
                            if (iIntValue2 < iMax3) {
                                if (arrayList6 == null) {
                                    arrayList6 = new ArrayList();
                                }
                                arrayList6.add(vVar.invoke(Integer.valueOf(iIntValue2)));
                            }
                            i55 = i57 + 1;
                            list4 = list5;
                            size = i56;
                        }
                        List list6 = list4;
                        if (arrayList6 == null) {
                            arrayList6 = kotlin.collections.K.a;
                        }
                        List list7 = arrayList6;
                        int size2 = list7.size();
                        int iMax4 = i7;
                        int i58 = 0;
                        while (i58 < size2) {
                            iMax4 = Math.max(iMax4, ((C0472k) list7.get(i58)).j);
                            i58++;
                            list7 = list7;
                        }
                        List list8 = list7;
                        int i59 = ((C0472k) c4927s.last()).a;
                        int i60 = iMax4;
                        U u10 = u2;
                        v vVar2 = new v(u10, j6, uVar4, j, hVar3, i28, 0);
                        int iMin = Math.min(i59 + i19, iIntValue - 1);
                        int i61 = i59 + 1;
                        ArrayList arrayList7 = null;
                        if (i61 <= iMin) {
                            while (true) {
                                if (arrayList7 == null) {
                                    arrayList7 = new ArrayList();
                                }
                                arrayList7.add(vVar2.invoke(Integer.valueOf(i61)));
                                if (i61 != iMin) {
                                    i61++;
                                }
                            }
                        }
                        int size3 = list6.size();
                        List arrayList8 = arrayList7;
                        for (int i62 = 0; i62 < size3; i62++) {
                            int iIntValue3 = ((Number) list6.get(i62)).intValue();
                            if (iMin + 1 <= iIntValue3 && iIntValue3 < iIntValue) {
                                if (arrayList8 == null) {
                                    arrayList8 = new ArrayList();
                                }
                                arrayList8.add(vVar2.invoke(Integer.valueOf(iIntValue3)));
                            }
                        }
                        if (arrayList8 == null) {
                            arrayList8 = kotlin.collections.K.a;
                        }
                        int size4 = arrayList8.size();
                        int iMax5 = i60;
                        for (int i63 = 0; i63 < size4; i63++) {
                            iMax5 = Math.max(iMax5, ((C0472k) arrayList8.get(i63)).j);
                        }
                        boolean z4 = Intrinsics.b(c0472k, c4927s.first()) && list8.isEmpty() && arrayList8.isEmpty();
                        int iL = L5.l(i33, jO);
                        int iK = L5.k(iMax5, jO);
                        boolean z5 = i33 < Math.min(iL, iH);
                        if (z5 && i52 != 0) {
                            throw new IllegalStateException(android.support.v4.media.session.a.f(i52, "non-zero pagesScrollOffset=").toString());
                        }
                        ArrayList arrayList9 = new ArrayList(arrayList8.size() + list8.size() + c4927s.a());
                        if (!z5) {
                            c0466e = c0466e2;
                            c0472k2 = c0472k;
                            i8 = iL;
                            z = z4;
                            i9 = i53;
                            i10 = i5;
                            obj3 = null;
                            i11 = i33;
                            int size5 = list8.size();
                            int i64 = i52;
                            int i65 = 0;
                            while (i65 < size5) {
                                int i66 = size5;
                                C0472k c0472k5 = (C0472k) list8.get(i65);
                                i64 -= i15;
                                c0472k5.b(i64, i8, iK);
                                arrayList9.add(c0472k5);
                                i65++;
                                size5 = i66;
                            }
                            list = list8;
                            int iA = c4927s.a();
                            for (int i67 = 0; i67 < iA; i67++) {
                                C0472k c0472k6 = (C0472k) c4927s.get(i67);
                                c0472k6.b(i52, i8, iK);
                                arrayList9.add(c0472k6);
                                i52 += i15;
                            }
                            int size6 = arrayList8.size();
                            for (int i68 = 0; i68 < size6; i68++) {
                                C0472k c0472k7 = (C0472k) arrayList8.get(i68);
                                c0472k7.b(i52, i8, iK);
                                arrayList9.add(c0472k7);
                                i52 += i15;
                            }
                        } else {
                            if (!list8.isEmpty() || !arrayList8.isEmpty()) {
                                throw new IllegalArgumentException("No extra pages");
                            }
                            int iA2 = c4927s.a();
                            int[] iArr = new int[iA2];
                            for (int i69 = 0; i69 < iA2; i69++) {
                                iArr[i69] = i28;
                            }
                            int[] iArr2 = new int[iA2];
                            for (int i70 = 0; i70 < iA2; i70++) {
                                iArr2[i70] = 0;
                            }
                            c0472k2 = c0472k;
                            obj3 = null;
                            iM05 = iM05;
                            i9 = i53;
                            c0466e = c0466e2;
                            z = z4;
                            i11 = i33;
                            i10 = i5;
                            new C0392j(f0Var.O(iM05), false, null).c(u10, iL, iArr, androidx.compose.ui.unit.k.a, iArr2);
                            i8 = iL;
                            IntRange intRangeC = C4933y.C(iArr2);
                            int i71 = intRangeC.a;
                            int i72 = intRangeC.b;
                            int i73 = intRangeC.c;
                            if ((i73 > 0 && i71 <= i72) || (i73 < 0 && i72 <= i71)) {
                                while (true) {
                                    int i74 = iArr2[i71];
                                    int i75 = i73;
                                    C0472k c0472k8 = (C0472k) c4927s.get(i71);
                                    c0472k8.b(i74, i8, iK);
                                    arrayList9.add(c0472k8);
                                    if (i71 != i72) {
                                        i71 += i75;
                                        i73 = i75;
                                    }
                                }
                            }
                            list = list8;
                        }
                        if (z) {
                            arrayList2 = arrayList9;
                        } else {
                            arrayList2 = new ArrayList(arrayList9.size());
                            int size7 = arrayList9.size();
                            int i76 = 0;
                            while (i76 < size7) {
                                Object obj11 = arrayList9.get(i76);
                                C4927s c4927s2 = c4927s;
                                C0472k c0472k9 = (C0472k) obj11;
                                int i77 = size7;
                                int i78 = i76;
                                if (c0472k9.a >= ((C0472k) c4927s2.first()).a) {
                                    if (c0472k9.a <= ((C0472k) c4927s2.last()).a) {
                                        arrayList2.add(obj11);
                                    }
                                }
                                i76 = i78 + 1;
                                c4927s = c4927s2;
                                size7 = i77;
                            }
                        }
                        C4927s c4927s3 = c4927s;
                        if (list.isEmpty()) {
                            arrayList3 = kotlin.collections.K.a;
                        } else {
                            arrayList3 = new ArrayList(arrayList9.size());
                            int size8 = arrayList9.size();
                            int i79 = 0;
                            while (i79 < size8) {
                                Object obj12 = arrayList9.get(i79);
                                int i80 = size8;
                                if (((C0472k) obj12).a < ((C0472k) c4927s3.first()).a) {
                                    arrayList3.add(obj12);
                                }
                                i79++;
                                size8 = i80;
                            }
                        }
                        List list9 = arrayList3;
                        if (arrayList8.isEmpty()) {
                            arrayList4 = kotlin.collections.K.a;
                        } else {
                            arrayList4 = new ArrayList(arrayList9.size());
                            int size9 = arrayList9.size();
                            for (int i81 = 0; i81 < size9; i81++) {
                                Object obj13 = arrayList9.get(i81);
                                if (((C0472k) obj13).a > ((C0472k) c4927s3.last()).a) {
                                    arrayList4.add(obj13);
                                }
                            }
                        }
                        List list10 = arrayList4;
                        if (arrayList2.isEmpty()) {
                            obj4 = obj3;
                        } else {
                            Object obj14 = arrayList2.get(0);
                            int i82 = ((C0472k) obj14).l;
                            nVar2.getClass();
                            float f2 = -Math.abs(i82 - f);
                            int i83 = kotlin.collections.B.i(arrayList2);
                            if (1 <= i83) {
                                int i84 = 1;
                                while (true) {
                                    Object obj15 = arrayList2.get(i84);
                                    float f3 = -Math.abs(((C0472k) obj15).l - f);
                                    if (Float.compare(f2, f3) < 0) {
                                        obj14 = obj15;
                                        f2 = f3;
                                    }
                                    if (i84 != i83) {
                                        i84++;
                                    }
                                }
                            }
                            obj4 = obj14;
                        }
                        C0472k c0472k10 = (C0472k) obj4;
                        nVar2.getClass();
                        xVar = new x(arrayList2, i28, iM05, i13, i22, i30, i19, c0472k2, c0472k10, i10 == 0 ? DefinitionKt.NO_Float_VALUE : kotlin.ranges.l.b((0 - (c0472k10 != null ? c0472k10.l : 0)) / i10, -0.5f, 0.5f), i6, i9 < iIntValue || i11 > iH, nVar2, (L) lVar3.invoke(Integer.valueOf(i8), Integer.valueOf(iK), new androidx.compose.foundation.lazy.grid.p(arrayList9, c0466e.B, 1)), z3, list9, list10);
                    }
                    x xVar2 = xVar;
                    c0466e.h(xVar2, false);
                    return xVar2;
                } catch (Throwable th) {
                    androidx.compose.runtime.snapshots.r.g(hVarD, hVarE, function1E);
                    throw th;
                }
            default:
                ((Number) obj2).intValue();
                androidx.compose.ui.q qVar = (androidx.compose.ui.q) obj7;
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) obj6;
                androidx.compose.runtime.internal.d dVar2 = (androidx.compose.runtime.internal.d) obj5;
                androidx.compose.runtime.internal.d dVar3 = (androidx.compose.runtime.internal.d) interfaceC4938g;
                Z0.a(qVar, dVar, dVar2, dVar3, (C0699p0) obj9, (androidx.compose.ui.text.L) obj8, this.b, (androidx.compose.runtime.internal.d) obj10, (InterfaceC0806l) obj, C0776c.H(1 | this.c));
                return Unit.a;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public w(androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, C0699p0 c0699p0, androidx.compose.ui.text.L l, float f, androidx.compose.runtime.internal.d dVar4, int i) {
        super(2);
        this.d = qVar;
        this.e = dVar;
        this.f = dVar2;
        this.g = dVar3;
        this.h = c0699p0;
        this.i = l;
        this.b = f;
        this.j = dVar4;
        this.c = i;
    }
}
