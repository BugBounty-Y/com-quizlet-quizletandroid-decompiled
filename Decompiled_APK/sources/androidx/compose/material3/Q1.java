package androidx.compose.material3;

import androidx.compose.ui.layout.AbstractC0882c;
import androidx.compose.ui.layout.InterfaceC0894o;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_barcode.S5;
import java.util.ArrayList;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class Q1 implements androidx.compose.ui.layout.N {
    public static int a(InterfaceC0894o interfaceC0894o, ArrayList arrayList, int i, Function2 function2) {
        int iIntValue;
        int iIntValue2;
        int i2 = i;
        List list = (List) arrayList.get(0);
        int i3 = 1;
        List list2 = (List) arrayList.get(1);
        List list3 = (List) arrayList.get(2);
        List list4 = (List) arrayList.get(3);
        List list5 = (List) arrayList.get(4);
        int iM0 = interfaceC0894o.m0(L1.c + L1.d);
        if (i2 != Integer.MAX_VALUE) {
            i2 -= iM0;
        }
        androidx.compose.ui.layout.J j = (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list4);
        if (j != null) {
            iIntValue = ((Number) function2.invoke(j, Integer.valueOf(i2))).intValue();
            int iZ = j.z(SubsamplingScaleImageView.TILE_SIZE_AUTO);
            if (i2 != Integer.MAX_VALUE) {
                i2 -= iZ;
            }
        } else {
            iIntValue = 0;
        }
        androidx.compose.ui.layout.J j2 = (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list5);
        if (j2 != null) {
            iIntValue2 = ((Number) function2.invoke(j2, Integer.valueOf(i2))).intValue();
            int iZ2 = j2.z(SubsamplingScaleImageView.TILE_SIZE_AUTO);
            if (i2 != Integer.MAX_VALUE) {
                i2 -= iZ2;
            }
        } else {
            iIntValue2 = 0;
        }
        Object obj = (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list2);
        int iIntValue3 = obj != null ? ((Number) function2.invoke(obj, Integer.valueOf(i2))).intValue() : 0;
        Object obj2 = (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list);
        int iIntValue4 = obj2 != null ? ((Number) function2.invoke(obj2, Integer.valueOf(i2))).intValue() : 0;
        Object obj3 = (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list3);
        int iIntValue5 = obj3 != null ? ((Number) function2.invoke(obj3, Integer.valueOf(i2))).intValue() : 0;
        boolean z = iIntValue5 > interfaceC0894o.j0(S5.g(30));
        boolean z2 = iIntValue3 > 0;
        boolean z3 = iIntValue5 > 0;
        if ((z2 && z3) || z) {
            i3 = 3;
        } else if (z2 || z3) {
            i3 = 2;
        }
        return L1.d(interfaceC0894o, iIntValue, iIntValue2, iIntValue4, iIntValue3, iIntValue5, i3, interfaceC0894o.m0((i3 == 3 ? L1.b : L1.a) * 2), L5.b(0, 0, 15));
    }

    public static int b(InterfaceC0894o interfaceC0894o, ArrayList arrayList, int i, Function2 function2) {
        List list = (List) arrayList.get(0);
        List list2 = (List) arrayList.get(1);
        List list3 = (List) arrayList.get(2);
        List list4 = (List) arrayList.get(3);
        List list5 = (List) arrayList.get(4);
        androidx.compose.ui.layout.J j = (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list4);
        int iIntValue = j != null ? ((Number) function2.invoke(j, Integer.valueOf(i))).intValue() : 0;
        androidx.compose.ui.layout.J j2 = (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list5);
        int iIntValue2 = j2 != null ? ((Number) function2.invoke(j2, Integer.valueOf(i))).intValue() : 0;
        androidx.compose.ui.layout.J j3 = (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list);
        int iIntValue3 = j3 != null ? ((Number) function2.invoke(j3, Integer.valueOf(i))).intValue() : 0;
        androidx.compose.ui.layout.J j4 = (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list2);
        int iIntValue4 = j4 != null ? ((Number) function2.invoke(j4, Integer.valueOf(i))).intValue() : 0;
        androidx.compose.ui.layout.J j5 = (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list3);
        int iIntValue5 = j5 != null ? ((Number) function2.invoke(j5, Integer.valueOf(i))).intValue() : 0;
        int iM0 = interfaceC0894o.m0(L1.c + L1.d);
        long jB = L5.b(0, 0, 15);
        if (androidx.compose.ui.unit.a.d(jB)) {
            return androidx.compose.ui.unit.a.h(jB);
        }
        return iM0 + iIntValue + Math.max(iIntValue3, Math.max(iIntValue4, iIntValue5)) + iIntValue2;
    }

    @Override // androidx.compose.ui.layout.N
    public final int maxIntrinsicHeight(InterfaceC0894o interfaceC0894o, List list, int i) {
        return a(interfaceC0894o, (ArrayList) list, i, M1.a);
    }

    @Override // androidx.compose.ui.layout.N
    public final int maxIntrinsicWidth(InterfaceC0894o interfaceC0894o, List list, int i) {
        return b(interfaceC0894o, (ArrayList) list, i, N1.a);
    }

    @Override // androidx.compose.ui.layout.N
    /* renamed from: measure-3p2s80s */
    public final androidx.compose.ui.layout.L mo2measure3p2s80s(androidx.compose.ui.layout.M m, List list, long j) {
        List list2;
        List list3;
        androidx.compose.ui.layout.W wB;
        int i;
        androidx.compose.ui.layout.W wB2;
        float f;
        androidx.compose.ui.layout.W wB3;
        int i2;
        int i3;
        ArrayList arrayList = (ArrayList) list;
        List list4 = (List) arrayList.get(0);
        List list5 = (List) arrayList.get(1);
        List list6 = (List) arrayList.get(2);
        List list7 = (List) arrayList.get(3);
        List list8 = (List) arrayList.get(4);
        long jA = androidx.compose.ui.unit.a.a(j, 0, 0, 0, 0, 10);
        float f2 = L1.c;
        float f3 = L1.d;
        int iM0 = m.m0(f2 + f3);
        androidx.compose.ui.layout.J j2 = (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list7);
        int iX = j2 != null ? j2.x(androidx.compose.ui.unit.a.g(j)) : 0;
        androidx.compose.ui.layout.J j3 = (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list8);
        int iX2 = j3 != null ? j3.x(androidx.compose.ui.unit.a.g(j)) : 0;
        int iH = androidx.compose.ui.unit.a.h(jA);
        int i4 = iX + iX2 + iM0;
        if (iH != Integer.MAX_VALUE) {
            iH -= i4;
        }
        androidx.compose.ui.layout.J j4 = (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list6);
        float f4 = (((CollectionsKt.firstOrNull(list5) != null) && (CollectionsKt.firstOrNull(list6) != null)) || ((j4 != null ? j4.X(iH) : 0) > m.j0(S5.g(30)))) ? L1.b : L1.a;
        float f5 = 2;
        long jO = L5.o(-iM0, -m.m0(f4 * f5), jA);
        androidx.compose.ui.layout.J j5 = (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list7);
        androidx.compose.ui.layout.W wB4 = j5 != null ? j5.B(jO) : null;
        float f6 = androidx.compose.material3.internal.Y.b;
        int i5 = wB4 != null ? wB4.a : 0;
        androidx.compose.ui.layout.J j6 = (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list8);
        if (j6 != null) {
            list2 = list4;
            list3 = list5;
            wB = j6.B(L5.p(jO, -i5, 0, 2));
        } else {
            list2 = list4;
            list3 = list5;
            wB = null;
        }
        int i6 = i5 + (wB != null ? wB.a : 0);
        androidx.compose.ui.layout.J j7 = (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list2);
        if (j7 != null) {
            i = 2;
            wB2 = j7.B(L5.p(jO, -i6, 0, 2));
        } else {
            i = 2;
            wB2 = null;
        }
        int i7 = wB2 != null ? wB2.b : 0;
        androidx.compose.ui.layout.J j8 = (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list6);
        if (j8 != null) {
            f = f5;
            wB3 = j8.B(L5.o(-i6, -i7, jO));
        } else {
            f = f5;
            wB3 = null;
        }
        int i8 = i7 + (wB3 != null ? wB3.b : 0);
        boolean z = (wB3 == null || wB3.d0(AbstractC0882c.a) == wB3.d0(AbstractC0882c.b)) ? false : true;
        androidx.compose.ui.layout.J j9 = (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list3);
        androidx.compose.ui.layout.W wB5 = j9 != null ? j9.B(L5.o(-i6, -i8, jO)) : null;
        boolean z2 = wB5 != null;
        boolean z3 = wB3 != null;
        if ((z2 && z3) || z) {
            i3 = 3;
            i2 = 3;
        } else if (z2 || z3) {
            i2 = i;
            i3 = 3;
        } else {
            i3 = 3;
            i2 = 1;
        }
        float f7 = i2 == i3 ? L1.b : L1.a;
        float f8 = f7 * f;
        int iH2 = androidx.compose.ui.unit.a.d(j) ? androidx.compose.ui.unit.a.h(j) : iM0 + (wB4 != null ? wB4.a : 0) + Math.max(wB2 != null ? wB2.a : 0, Math.max(wB5 != null ? wB5.a : 0, wB3 != null ? wB3.a : 0)) + (wB != null ? wB.a : 0);
        androidx.compose.ui.layout.W w = wB2;
        androidx.compose.ui.layout.W w2 = wB5;
        int iD = L1.d(m, wB4 != null ? wB4.b : 0, wB != null ? wB.b : 0, wB2 != null ? wB2.b : 0, wB5 != null ? wB5.b : 0, wB3 != null ? wB3.b : 0, i2, m.m0(f8), j);
        return m.n0(iH2, iD, kotlin.collections.V.c(), new K1(wB4, wB, m.m0(f2), i2 == 3, m.m0(f7), w, w2, wB3, iD, iH2, m.m0(f3)));
    }

    @Override // androidx.compose.ui.layout.N
    public final int minIntrinsicHeight(InterfaceC0894o interfaceC0894o, List list, int i) {
        return a(interfaceC0894o, (ArrayList) list, i, O1.a);
    }

    @Override // androidx.compose.ui.layout.N
    public final int minIntrinsicWidth(InterfaceC0894o interfaceC0894o, List list, int i) {
        return b(interfaceC0894o, (ArrayList) list, i, P1.a);
    }
}
