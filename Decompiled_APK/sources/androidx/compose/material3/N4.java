package androidx.compose.material3;

import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.layout.InterfaceC0894o;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class N4 implements androidx.compose.ui.layout.K {
    public final boolean a;
    public final float b;
    public final androidx.compose.foundation.layout.A0 c;

    public N4(boolean z, float f, androidx.compose.foundation.layout.A0 a0) {
        this.a = z;
        this.b = f;
        this.c = a0;
    }

    public static int b(List list, int i, Function2 function2) {
        Object obj;
        Object obj2;
        Object obj3;
        Object obj4;
        Object obj5;
        Object obj6;
        int size = list.size();
        for (int i2 = 0; i2 < size; i2++) {
            Object obj7 = list.get(i2);
            if (Intrinsics.b(androidx.compose.material3.internal.Y.f((androidx.compose.ui.layout.J) obj7), "TextField")) {
                int iIntValue = ((Number) function2.invoke(obj7, Integer.valueOf(i))).intValue();
                int size2 = list.size();
                int i3 = 0;
                while (true) {
                    obj = null;
                    if (i3 >= size2) {
                        obj2 = null;
                        break;
                    }
                    obj2 = list.get(i3);
                    if (Intrinsics.b(androidx.compose.material3.internal.Y.f((androidx.compose.ui.layout.J) obj2), "Label")) {
                        break;
                    }
                    i3++;
                }
                androidx.compose.ui.layout.J j = (androidx.compose.ui.layout.J) obj2;
                int iIntValue2 = j != null ? ((Number) function2.invoke(j, Integer.valueOf(i))).intValue() : 0;
                int size3 = list.size();
                int i4 = 0;
                while (true) {
                    if (i4 >= size3) {
                        obj3 = null;
                        break;
                    }
                    obj3 = list.get(i4);
                    if (Intrinsics.b(androidx.compose.material3.internal.Y.f((androidx.compose.ui.layout.J) obj3), "Trailing")) {
                        break;
                    }
                    i4++;
                }
                androidx.compose.ui.layout.J j2 = (androidx.compose.ui.layout.J) obj3;
                int iIntValue3 = j2 != null ? ((Number) function2.invoke(j2, Integer.valueOf(i))).intValue() : 0;
                int size4 = list.size();
                int i5 = 0;
                while (true) {
                    if (i5 >= size4) {
                        obj4 = null;
                        break;
                    }
                    obj4 = list.get(i5);
                    if (Intrinsics.b(androidx.compose.material3.internal.Y.f((androidx.compose.ui.layout.J) obj4), "Prefix")) {
                        break;
                    }
                    i5++;
                }
                androidx.compose.ui.layout.J j3 = (androidx.compose.ui.layout.J) obj4;
                int iIntValue4 = j3 != null ? ((Number) function2.invoke(j3, Integer.valueOf(i))).intValue() : 0;
                int size5 = list.size();
                int i6 = 0;
                while (true) {
                    if (i6 >= size5) {
                        obj5 = null;
                        break;
                    }
                    obj5 = list.get(i6);
                    if (Intrinsics.b(androidx.compose.material3.internal.Y.f((androidx.compose.ui.layout.J) obj5), "Suffix")) {
                        break;
                    }
                    i6++;
                }
                androidx.compose.ui.layout.J j4 = (androidx.compose.ui.layout.J) obj5;
                int iIntValue5 = j4 != null ? ((Number) function2.invoke(j4, Integer.valueOf(i))).intValue() : 0;
                int size6 = list.size();
                int i7 = 0;
                while (true) {
                    if (i7 >= size6) {
                        obj6 = null;
                        break;
                    }
                    obj6 = list.get(i7);
                    if (Intrinsics.b(androidx.compose.material3.internal.Y.f((androidx.compose.ui.layout.J) obj6), "Leading")) {
                        break;
                    }
                    i7++;
                }
                androidx.compose.ui.layout.J j5 = (androidx.compose.ui.layout.J) obj6;
                int iIntValue6 = j5 != null ? ((Number) function2.invoke(j5, Integer.valueOf(i))).intValue() : 0;
                int size7 = list.size();
                int i8 = 0;
                while (true) {
                    if (i8 >= size7) {
                        break;
                    }
                    Object obj8 = list.get(i8);
                    if (Intrinsics.b(androidx.compose.material3.internal.Y.f((androidx.compose.ui.layout.J) obj8), "Hint")) {
                        obj = obj8;
                        break;
                    }
                    i8++;
                }
                androidx.compose.ui.layout.J j6 = (androidx.compose.ui.layout.J) obj;
                int iIntValue7 = j6 != null ? ((Number) function2.invoke(j6, Integer.valueOf(i))).intValue() : 0;
                long j7 = androidx.compose.material3.internal.Y.a;
                float f = K4.a;
                int i9 = iIntValue4 + iIntValue5;
                return Math.max(Math.max(iIntValue + i9, Math.max(iIntValue7 + i9, iIntValue2)) + iIntValue6 + iIntValue3, androidx.compose.ui.unit.a.j(j7));
            }
        }
        throw new NoSuchElementException("Collection contains no element matching the predicate.");
    }

    public final int a(InterfaceC0894o interfaceC0894o, List list, int i, Function2 function2) {
        Object obj;
        int iZ;
        int iIntValue;
        Object obj2;
        int iIntValue2;
        Object obj3;
        Object obj4;
        int i2;
        Object obj5;
        int i3;
        Object obj6;
        Object obj7;
        int size = list.size();
        int i4 = 0;
        while (true) {
            if (i4 >= size) {
                obj = null;
                break;
            }
            obj = list.get(i4);
            if (Intrinsics.b(androidx.compose.material3.internal.Y.f((androidx.compose.ui.layout.J) obj), "Leading")) {
                break;
            }
            i4++;
        }
        androidx.compose.ui.layout.J j = (androidx.compose.ui.layout.J) obj;
        if (j != null) {
            iZ = i == Integer.MAX_VALUE ? i : i - j.z(SubsamplingScaleImageView.TILE_SIZE_AUTO);
            iIntValue = ((Number) function2.invoke(j, Integer.valueOf(i))).intValue();
        } else {
            iZ = i;
            iIntValue = 0;
        }
        int size2 = list.size();
        int i5 = 0;
        while (true) {
            if (i5 >= size2) {
                obj2 = null;
                break;
            }
            obj2 = list.get(i5);
            if (Intrinsics.b(androidx.compose.material3.internal.Y.f((androidx.compose.ui.layout.J) obj2), "Trailing")) {
                break;
            }
            i5++;
        }
        androidx.compose.ui.layout.J j2 = (androidx.compose.ui.layout.J) obj2;
        if (j2 != null) {
            int iZ2 = j2.z(SubsamplingScaleImageView.TILE_SIZE_AUTO);
            if (iZ != Integer.MAX_VALUE) {
                iZ -= iZ2;
            }
            iIntValue2 = ((Number) function2.invoke(j2, Integer.valueOf(i))).intValue();
        } else {
            iIntValue2 = 0;
        }
        int size3 = list.size();
        int i6 = 0;
        while (true) {
            if (i6 >= size3) {
                obj3 = null;
                break;
            }
            obj3 = list.get(i6);
            if (Intrinsics.b(androidx.compose.material3.internal.Y.f((androidx.compose.ui.layout.J) obj3), "Label")) {
                break;
            }
            i6++;
        }
        Object obj8 = (androidx.compose.ui.layout.J) obj3;
        int iIntValue3 = obj8 != null ? ((Number) function2.invoke(obj8, Integer.valueOf(iZ))).intValue() : 0;
        int size4 = list.size();
        int i7 = 0;
        while (true) {
            if (i7 >= size4) {
                obj4 = null;
                break;
            }
            obj4 = list.get(i7);
            if (Intrinsics.b(androidx.compose.material3.internal.Y.f((androidx.compose.ui.layout.J) obj4), "Prefix")) {
                break;
            }
            i7++;
        }
        androidx.compose.ui.layout.J j3 = (androidx.compose.ui.layout.J) obj4;
        if (j3 != null) {
            int iIntValue4 = ((Number) function2.invoke(j3, Integer.valueOf(iZ))).intValue();
            int iZ3 = j3.z(SubsamplingScaleImageView.TILE_SIZE_AUTO);
            if (iZ != Integer.MAX_VALUE) {
                iZ -= iZ3;
            }
            i2 = iIntValue4;
        } else {
            i2 = 0;
        }
        int size5 = list.size();
        int i8 = 0;
        while (true) {
            if (i8 >= size5) {
                obj5 = null;
                break;
            }
            obj5 = list.get(i8);
            if (Intrinsics.b(androidx.compose.material3.internal.Y.f((androidx.compose.ui.layout.J) obj5), "Suffix")) {
                break;
            }
            i8++;
        }
        androidx.compose.ui.layout.J j4 = (androidx.compose.ui.layout.J) obj5;
        if (j4 != null) {
            int iIntValue5 = ((Number) function2.invoke(j4, Integer.valueOf(iZ))).intValue();
            int iZ4 = j4.z(SubsamplingScaleImageView.TILE_SIZE_AUTO);
            if (iZ != Integer.MAX_VALUE) {
                iZ -= iZ4;
            }
            i3 = iIntValue5;
        } else {
            i3 = 0;
        }
        int size6 = list.size();
        for (int i9 = 0; i9 < size6; i9++) {
            Object obj9 = list.get(i9);
            if (Intrinsics.b(androidx.compose.material3.internal.Y.f((androidx.compose.ui.layout.J) obj9), "TextField")) {
                int iIntValue6 = ((Number) function2.invoke(obj9, Integer.valueOf(iZ))).intValue();
                int size7 = list.size();
                int i10 = 0;
                while (true) {
                    if (i10 >= size7) {
                        obj6 = null;
                        break;
                    }
                    obj6 = list.get(i10);
                    if (Intrinsics.b(androidx.compose.material3.internal.Y.f((androidx.compose.ui.layout.J) obj6), "Hint")) {
                        break;
                    }
                    i10++;
                }
                Object obj10 = (androidx.compose.ui.layout.J) obj6;
                int iIntValue7 = obj10 != null ? ((Number) function2.invoke(obj10, Integer.valueOf(iZ))).intValue() : 0;
                int size8 = list.size();
                int i11 = 0;
                while (true) {
                    if (i11 >= size8) {
                        obj7 = null;
                        break;
                    }
                    Object obj11 = list.get(i11);
                    if (Intrinsics.b(androidx.compose.material3.internal.Y.f((androidx.compose.ui.layout.J) obj11), "Supporting")) {
                        obj7 = obj11;
                        break;
                    }
                    i11++;
                }
                Object obj12 = (androidx.compose.ui.layout.J) obj7;
                return K4.d(iIntValue6, iIntValue3, iIntValue, iIntValue2, i2, i3, iIntValue7, obj12 != null ? ((Number) function2.invoke(obj12, Integer.valueOf(i))).intValue() : 0, this.b, androidx.compose.material3.internal.Y.a, interfaceC0894o.a(), this.c);
            }
        }
        throw new NoSuchElementException("Collection contains no element matching the predicate.");
    }

    @Override // androidx.compose.ui.layout.K
    public final int maxIntrinsicHeight(InterfaceC0894o interfaceC0894o, List list, int i) {
        return a(interfaceC0894o, list, i, C0602d0.D);
    }

    @Override // androidx.compose.ui.layout.K
    public final int maxIntrinsicWidth(InterfaceC0894o interfaceC0894o, List list, int i) {
        return b(list, i, C0602d0.E);
    }

    @Override // androidx.compose.ui.layout.K
    /* renamed from: measure-3p2s80s */
    public final androidx.compose.ui.layout.L mo1measure3p2s80s(androidx.compose.ui.layout.M m, List list, long j) {
        Object obj;
        int i;
        Object obj2;
        Object obj3;
        int i2;
        androidx.compose.ui.layout.W wB;
        Object obj4;
        int i3;
        Object obj5;
        Object obj6;
        Object obj7;
        int i4;
        androidx.compose.ui.layout.W wB2;
        N4 n4 = this;
        List list2 = list;
        int i5 = 1;
        androidx.compose.foundation.layout.A0 a0 = n4.c;
        int iM0 = m.m0(a0.b);
        int iM02 = m.m0(a0.d);
        long jA = androidx.compose.ui.unit.a.a(j, 0, 0, 0, 0, 10);
        int size = list2.size();
        int i6 = 0;
        while (true) {
            if (i6 >= size) {
                obj = null;
                break;
            }
            obj = list2.get(i6);
            if (Intrinsics.b(AbstractC0897s.h((androidx.compose.ui.layout.J) obj), "Leading")) {
                break;
            }
            i6++;
        }
        androidx.compose.ui.layout.J j2 = (androidx.compose.ui.layout.J) obj;
        androidx.compose.ui.layout.W wB3 = j2 != null ? j2.B(jA) : null;
        float f = androidx.compose.material3.internal.Y.b;
        int i7 = wB3 != null ? wB3.a : 0;
        int iMax = Math.max(0, wB3 != null ? wB3.b : 0);
        int size2 = list2.size();
        int i8 = 0;
        while (true) {
            if (i8 >= size2) {
                i = i5;
                obj2 = null;
                break;
            }
            obj2 = list2.get(i8);
            i = i5;
            if (Intrinsics.b(AbstractC0897s.h((androidx.compose.ui.layout.J) obj2), "Trailing")) {
                break;
            }
            i8++;
            i5 = i;
        }
        androidx.compose.ui.layout.J j3 = (androidx.compose.ui.layout.J) obj2;
        androidx.compose.ui.layout.W wB4 = j3 != null ? j3.B(L5.p(jA, -i7, 0, 2)) : null;
        int i9 = i7 + (wB4 != null ? wB4.a : 0);
        int iMax2 = Math.max(iMax, wB4 != null ? wB4.b : 0);
        int size3 = list2.size();
        int i10 = 0;
        while (true) {
            if (i10 >= size3) {
                obj3 = null;
                break;
            }
            obj3 = list2.get(i10);
            if (Intrinsics.b(AbstractC0897s.h((androidx.compose.ui.layout.J) obj3), "Prefix")) {
                break;
            }
            i10++;
        }
        androidx.compose.ui.layout.J j4 = (androidx.compose.ui.layout.J) obj3;
        if (j4 != null) {
            i2 = iM0;
            wB = j4.B(L5.p(jA, -i9, 0, 2));
        } else {
            i2 = iM0;
            wB = null;
        }
        int i11 = i9 + (wB != null ? wB.a : 0);
        int iMax3 = Math.max(iMax2, wB != null ? wB.b : 0);
        int size4 = list2.size();
        int i12 = 0;
        while (true) {
            if (i12 >= size4) {
                obj4 = null;
                break;
            }
            obj4 = list2.get(i12);
            if (Intrinsics.b(AbstractC0897s.h((androidx.compose.ui.layout.J) obj4), "Suffix")) {
                break;
            }
            i12++;
        }
        androidx.compose.ui.layout.J j5 = (androidx.compose.ui.layout.J) obj4;
        androidx.compose.ui.layout.W wB5 = j5 != null ? j5.B(L5.p(jA, -i11, 0, 2)) : null;
        int i13 = i11 + (wB5 != null ? wB5.a : 0);
        int iMax4 = Math.max(iMax3, wB5 != null ? wB5.b : 0);
        int i14 = -i13;
        long jO = L5.o(i14, -iM02, jA);
        int size5 = list2.size();
        int i15 = 0;
        while (true) {
            if (i15 >= size5) {
                i3 = iM02;
                obj5 = null;
                break;
            }
            obj5 = list2.get(i15);
            i3 = iM02;
            int i16 = size5;
            if (Intrinsics.b(AbstractC0897s.h((androidx.compose.ui.layout.J) obj5), "Label")) {
                break;
            }
            i15++;
            size5 = i16;
            iM02 = i3;
        }
        androidx.compose.ui.layout.J j6 = (androidx.compose.ui.layout.J) obj5;
        androidx.compose.ui.layout.W wB6 = j6 != null ? j6.B(jO) : null;
        int size6 = list2.size();
        int i17 = 0;
        while (true) {
            if (i17 >= size6) {
                obj6 = null;
                break;
            }
            obj6 = list2.get(i17);
            int i18 = size6;
            if (Intrinsics.b(AbstractC0897s.h((androidx.compose.ui.layout.J) obj6), "Supporting")) {
                break;
            }
            i17++;
            size6 = i18;
        }
        androidx.compose.ui.layout.J j7 = (androidx.compose.ui.layout.J) obj6;
        int iX = j7 != null ? j7.X(androidx.compose.ui.unit.a.j(j)) : 0;
        int i19 = (wB6 != null ? wB6.b : 0) + i2;
        int i20 = i2;
        long jO2 = L5.o(i14, ((-i19) - i3) - iX, androidx.compose.ui.unit.a.a(j, 0, 0, 0, 0, 11));
        int size7 = list2.size();
        int i21 = 0;
        while (i21 < size7) {
            int i22 = size7;
            androidx.compose.ui.layout.J j8 = (androidx.compose.ui.layout.J) list2.get(i21);
            int i23 = i21;
            if (Intrinsics.b(AbstractC0897s.h(j8), "TextField")) {
                androidx.compose.ui.layout.W wB7 = j8.B(jO2);
                long jA2 = androidx.compose.ui.unit.a.a(jO2, 0, 0, 0, 0, 14);
                int size8 = list2.size();
                int i24 = 0;
                while (true) {
                    if (i24 >= size8) {
                        obj7 = null;
                        break;
                    }
                    obj7 = list2.get(i24);
                    int i25 = size8;
                    int i26 = i24;
                    if (Intrinsics.b(AbstractC0897s.h((androidx.compose.ui.layout.J) obj7), "Hint")) {
                        break;
                    }
                    i24 = i26 + 1;
                    size8 = i25;
                }
                androidx.compose.ui.layout.J j9 = (androidx.compose.ui.layout.J) obj7;
                androidx.compose.ui.layout.W wB8 = j9 != null ? j9.B(jA2) : null;
                int iMax5 = Math.max(iMax4, Math.max(wB7.b, wB8 != null ? wB8.b : 0) + i19 + i3);
                int i27 = wB3 != null ? wB3.a : 0;
                int i28 = wB4 != null ? wB4.a : 0;
                int i29 = i27;
                int i30 = (wB != null ? wB.a : 0) + (wB5 != null ? wB5.a : 0);
                int iMax6 = Math.max(Math.max(wB7.a + i30, Math.max((wB8 != null ? wB8.a : 0) + i30, wB6 != null ? wB6.a : 0)) + i29 + i28, androidx.compose.ui.unit.a.j(j));
                long jA3 = androidx.compose.ui.unit.a.a(L5.p(jA, 0, -iMax5, i), 0, iMax6, 0, 0, 9);
                int i31 = iMax6;
                if (j7 != null) {
                    i4 = 0;
                    wB2 = j7.B(jA3);
                } else {
                    i4 = 0;
                    wB2 = null;
                }
                int i32 = wB2 != null ? wB2.b : i4;
                int iD = K4.d(wB7.b, wB6 != null ? wB6.b : i4, wB3 != null ? wB3.b : i4, wB4 != null ? wB4.b : i4, wB != null ? wB.b : i4, wB5 != null ? wB5.b : i4, wB8 != null ? wB8.b : i4, wB2 != null ? wB2.b : i4, n4.b, j, m.a(), n4.c);
                int i33 = iD - i32;
                int size9 = list2.size();
                int i34 = i4;
                while (i34 < size9) {
                    androidx.compose.ui.layout.J j10 = (androidx.compose.ui.layout.J) list2.get(i34);
                    androidx.compose.ui.layout.W w = wB;
                    if (Intrinsics.b(AbstractC0897s.h(j10), "Container")) {
                        androidx.compose.ui.layout.W wB9 = j10.B(L5.a(i31 != Integer.MAX_VALUE ? i31 : i4, i31, i33 != Integer.MAX_VALUE ? i33 : i4, i33));
                        int i35 = i31;
                        androidx.compose.ui.layout.W w2 = wB3;
                        int i36 = iD;
                        return m.n0(i35, i36, kotlin.collections.V.c(), new L4(wB6, i35, i36, wB7, wB8, w2, wB4, w, wB5, wB9, wB2, n4, i20, m));
                    }
                    i34++;
                    iD = iD;
                    wB3 = wB3;
                    wB4 = wB4;
                    wB7 = wB7;
                    n4 = this;
                    list2 = list;
                    wB2 = wB2;
                    i31 = i31;
                    wB6 = wB6;
                    wB = w;
                }
                throw new NoSuchElementException("Collection contains no element matching the predicate.");
            }
            i21 = i23 + 1;
            n4 = this;
            list2 = list;
            wB = wB;
            jO2 = jO2;
            wB4 = wB4;
            size7 = i22;
        }
        throw new NoSuchElementException("Collection contains no element matching the predicate.");
    }

    @Override // androidx.compose.ui.layout.K
    public final int minIntrinsicHeight(InterfaceC0894o interfaceC0894o, List list, int i) {
        return a(interfaceC0894o, list, i, M4.b);
    }

    @Override // androidx.compose.ui.layout.K
    public final int minIntrinsicWidth(InterfaceC0894o interfaceC0894o, List list, int i) {
        return b(list, i, M4.c);
    }
}
