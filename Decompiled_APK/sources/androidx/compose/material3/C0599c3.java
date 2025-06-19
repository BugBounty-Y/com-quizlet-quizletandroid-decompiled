package androidx.compose.material3;

import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.layout.InterfaceC0894o;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_barcode.V5;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.material3.c3, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0599c3 implements androidx.compose.ui.layout.K {
    public final Function1 a;
    public final boolean b;
    public final float c;
    public final androidx.compose.foundation.layout.A0 d;

    public C0599c3(Function1 function1, boolean z, float f, androidx.compose.foundation.layout.A0 a0) {
        this.a = function1;
        this.b = z;
        this.c = f;
        this.d = a0;
    }

    public final int a(InterfaceC0894o interfaceC0894o, List list, int i, Function2 function2) {
        Object obj;
        int iZ;
        int iIntValue;
        Object obj2;
        int iIntValue2;
        Object obj3;
        Object obj4;
        int iIntValue3;
        Object obj5;
        int i2;
        Object obj6;
        Object obj7;
        int size = list.size();
        int i3 = 0;
        while (true) {
            if (i3 >= size) {
                obj = null;
                break;
            }
            obj = list.get(i3);
            if (Intrinsics.b(androidx.compose.material3.internal.Y.f((androidx.compose.ui.layout.J) obj), "Leading")) {
                break;
            }
            i3++;
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
        int i4 = 0;
        while (true) {
            if (i4 >= size2) {
                obj2 = null;
                break;
            }
            obj2 = list.get(i4);
            if (Intrinsics.b(androidx.compose.material3.internal.Y.f((androidx.compose.ui.layout.J) obj2), "Trailing")) {
                break;
            }
            i4++;
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
        int i5 = 0;
        while (true) {
            if (i5 >= size3) {
                obj3 = null;
                break;
            }
            obj3 = list.get(i5);
            if (Intrinsics.b(androidx.compose.material3.internal.Y.f((androidx.compose.ui.layout.J) obj3), "Label")) {
                break;
            }
            i5++;
        }
        Object obj8 = (androidx.compose.ui.layout.J) obj3;
        int iIntValue4 = obj8 != null ? ((Number) function2.invoke(obj8, Integer.valueOf(V5.d(iZ, this.c, i)))).intValue() : 0;
        int size4 = list.size();
        int i6 = 0;
        while (true) {
            if (i6 >= size4) {
                obj4 = null;
                break;
            }
            obj4 = list.get(i6);
            if (Intrinsics.b(androidx.compose.material3.internal.Y.f((androidx.compose.ui.layout.J) obj4), "Prefix")) {
                break;
            }
            i6++;
        }
        androidx.compose.ui.layout.J j3 = (androidx.compose.ui.layout.J) obj4;
        if (j3 != null) {
            iIntValue3 = ((Number) function2.invoke(j3, Integer.valueOf(iZ))).intValue();
            int iZ3 = j3.z(SubsamplingScaleImageView.TILE_SIZE_AUTO);
            if (iZ != Integer.MAX_VALUE) {
                iZ -= iZ3;
            }
        } else {
            iIntValue3 = 0;
        }
        int size5 = list.size();
        int i7 = 0;
        while (true) {
            if (i7 >= size5) {
                obj5 = null;
                break;
            }
            obj5 = list.get(i7);
            if (Intrinsics.b(androidx.compose.material3.internal.Y.f((androidx.compose.ui.layout.J) obj5), "Suffix")) {
                break;
            }
            i7++;
        }
        androidx.compose.ui.layout.J j4 = (androidx.compose.ui.layout.J) obj5;
        if (j4 != null) {
            int iIntValue5 = ((Number) function2.invoke(j4, Integer.valueOf(iZ))).intValue();
            int iZ4 = j4.z(SubsamplingScaleImageView.TILE_SIZE_AUTO);
            if (iZ != Integer.MAX_VALUE) {
                iZ -= iZ4;
            }
            i2 = iIntValue5;
        } else {
            i2 = 0;
        }
        int size6 = list.size();
        for (int i8 = 0; i8 < size6; i8++) {
            Object obj9 = list.get(i8);
            if (Intrinsics.b(androidx.compose.material3.internal.Y.f((androidx.compose.ui.layout.J) obj9), "TextField")) {
                int iIntValue6 = ((Number) function2.invoke(obj9, Integer.valueOf(iZ))).intValue();
                int size7 = list.size();
                int i9 = 0;
                while (true) {
                    if (i9 >= size7) {
                        obj6 = null;
                        break;
                    }
                    obj6 = list.get(i9);
                    if (Intrinsics.b(androidx.compose.material3.internal.Y.f((androidx.compose.ui.layout.J) obj6), "Hint")) {
                        break;
                    }
                    i9++;
                }
                Object obj10 = (androidx.compose.ui.layout.J) obj6;
                int iIntValue7 = obj10 != null ? ((Number) function2.invoke(obj10, Integer.valueOf(iZ))).intValue() : 0;
                int size8 = list.size();
                int i10 = 0;
                while (true) {
                    if (i10 >= size8) {
                        obj7 = null;
                        break;
                    }
                    Object obj11 = list.get(i10);
                    if (Intrinsics.b(androidx.compose.material3.internal.Y.f((androidx.compose.ui.layout.J) obj11), "Supporting")) {
                        obj7 = obj11;
                        break;
                    }
                    i10++;
                }
                Object obj12 = (androidx.compose.ui.layout.J) obj7;
                return AbstractC0587a3.d(iIntValue, iIntValue2, iIntValue3, i2, iIntValue6, iIntValue4, iIntValue7, obj12 != null ? ((Number) function2.invoke(obj12, Integer.valueOf(i))).intValue() : 0, this.c, androidx.compose.material3.internal.Y.a, interfaceC0894o.a(), this.d);
            }
        }
        throw new NoSuchElementException("Collection contains no element matching the predicate.");
    }

    public final int b(InterfaceC0894o interfaceC0894o, List list, int i, Function2 function2) {
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
                    if (Intrinsics.b(androidx.compose.material3.internal.Y.f((androidx.compose.ui.layout.J) obj4), "Leading")) {
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
                    if (Intrinsics.b(androidx.compose.material3.internal.Y.f((androidx.compose.ui.layout.J) obj5), "Prefix")) {
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
                    if (Intrinsics.b(androidx.compose.material3.internal.Y.f((androidx.compose.ui.layout.J) obj6), "Suffix")) {
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
                return AbstractC0587a3.e(iIntValue4, iIntValue3, iIntValue5, iIntValue6, iIntValue, iIntValue2, j6 != null ? ((Number) function2.invoke(j6, Integer.valueOf(i))).intValue() : 0, this.c, androidx.compose.material3.internal.Y.a, interfaceC0894o.a(), this.d);
            }
        }
        throw new NoSuchElementException("Collection contains no element matching the predicate.");
    }

    @Override // androidx.compose.ui.layout.K
    public final int maxIntrinsicHeight(InterfaceC0894o interfaceC0894o, List list, int i) {
        return a(interfaceC0894o, list, i, C0602d0.x);
    }

    @Override // androidx.compose.ui.layout.K
    public final int maxIntrinsicWidth(InterfaceC0894o interfaceC0894o, List list, int i) {
        return b(interfaceC0894o, list, i, C0602d0.y);
    }

    @Override // androidx.compose.ui.layout.K
    /* renamed from: measure-3p2s80s */
    public final androidx.compose.ui.layout.L mo1measure3p2s80s(androidx.compose.ui.layout.M m, List list, long j) {
        Object obj;
        int i;
        Object obj2;
        int i2;
        androidx.compose.ui.layout.W wB;
        Object obj3;
        androidx.compose.ui.layout.W w;
        int i3;
        androidx.compose.ui.layout.W wB2;
        Object obj4;
        int i4;
        androidx.compose.ui.layout.W wB3;
        Object obj5;
        int i5;
        Object obj6;
        Object obj7;
        C0599c3 c0599c3 = this;
        List list2 = list;
        int i6 = 1;
        androidx.compose.foundation.layout.A0 a0 = c0599c3.d;
        int iM0 = m.m0(a0.d);
        long jA = androidx.compose.ui.unit.a.a(j, 0, 0, 0, 0, 10);
        int size = list2.size();
        int i7 = 0;
        while (true) {
            if (i7 >= size) {
                obj = null;
                break;
            }
            obj = list2.get(i7);
            if (Intrinsics.b(AbstractC0897s.h((androidx.compose.ui.layout.J) obj), "Leading")) {
                break;
            }
            i7++;
        }
        androidx.compose.ui.layout.J j2 = (androidx.compose.ui.layout.J) obj;
        androidx.compose.ui.layout.W wB4 = j2 != null ? j2.B(jA) : null;
        float f = androidx.compose.material3.internal.Y.b;
        int i8 = wB4 != null ? wB4.a : 0;
        int iMax = Math.max(0, wB4 != null ? wB4.b : 0);
        int size2 = list2.size();
        int i9 = 0;
        while (true) {
            if (i9 >= size2) {
                i = i6;
                obj2 = null;
                break;
            }
            obj2 = list2.get(i9);
            i = i6;
            if (Intrinsics.b(AbstractC0897s.h((androidx.compose.ui.layout.J) obj2), "Trailing")) {
                break;
            }
            i9++;
            i6 = i;
        }
        androidx.compose.ui.layout.J j3 = (androidx.compose.ui.layout.J) obj2;
        if (j3 != null) {
            i2 = i8;
            wB = j3.B(L5.p(jA, -i8, 0, 2));
        } else {
            i2 = i8;
            wB = null;
        }
        int i10 = (wB != null ? wB.a : 0) + i2;
        int iMax2 = Math.max(iMax, wB != null ? wB.b : 0);
        int size3 = list2.size();
        int i11 = 0;
        while (true) {
            if (i11 >= size3) {
                obj3 = null;
                break;
            }
            obj3 = list2.get(i11);
            if (Intrinsics.b(AbstractC0897s.h((androidx.compose.ui.layout.J) obj3), "Prefix")) {
                break;
            }
            i11++;
        }
        androidx.compose.ui.layout.J j4 = (androidx.compose.ui.layout.J) obj3;
        if (j4 != null) {
            w = wB;
            i3 = i10;
            wB2 = j4.B(L5.p(jA, -i10, 0, 2));
        } else {
            w = wB;
            i3 = i10;
            wB2 = null;
        }
        int i12 = i3 + (wB2 != null ? wB2.a : 0);
        int iMax3 = Math.max(iMax2, wB2 != null ? wB2.b : 0);
        int size4 = list2.size();
        int i13 = 0;
        while (true) {
            if (i13 >= size4) {
                obj4 = null;
                break;
            }
            obj4 = list2.get(i13);
            if (Intrinsics.b(AbstractC0897s.h((androidx.compose.ui.layout.J) obj4), "Suffix")) {
                break;
            }
            i13++;
        }
        androidx.compose.ui.layout.J j5 = (androidx.compose.ui.layout.J) obj4;
        if (j5 != null) {
            i4 = i12;
            wB3 = j5.B(L5.p(jA, -i12, 0, 2));
        } else {
            i4 = i12;
            wB3 = null;
        }
        int i14 = (wB3 != null ? wB3.a : 0) + i4;
        int iMax4 = Math.max(iMax3, wB3 != null ? wB3.b : 0);
        int iM02 = m.m0(a0.c(m.getLayoutDirection())) + m.m0(a0.b(m.getLayoutDirection()));
        int i15 = -i14;
        int iD = V5.d(i15 - iM02, c0599c3.c, -iM02);
        int i16 = -iM0;
        long jO = L5.o(iD, i16, jA);
        int size5 = list2.size();
        int i17 = 0;
        while (true) {
            if (i17 >= size5) {
                obj5 = null;
                break;
            }
            obj5 = list2.get(i17);
            int i18 = i17;
            int i19 = size5;
            if (Intrinsics.b(AbstractC0897s.h((androidx.compose.ui.layout.J) obj5), "Label")) {
                break;
            }
            i17 = i18 + 1;
            size5 = i19;
        }
        androidx.compose.ui.layout.J j6 = (androidx.compose.ui.layout.J) obj5;
        androidx.compose.ui.layout.W wB5 = j6 != null ? j6.B(jO) : null;
        c0599c3.a.invoke(new androidx.compose.ui.geometry.e(wB5 != null ? com.google.android.gms.internal.mlkit_vision_barcode.T4.a(wB5.a, wB5.b) : 0L));
        int size6 = list2.size();
        int i20 = 0;
        while (true) {
            if (i20 >= size6) {
                i5 = i16;
                obj6 = null;
                break;
            }
            obj6 = list2.get(i20);
            int i21 = size6;
            i5 = i16;
            if (Intrinsics.b(AbstractC0897s.h((androidx.compose.ui.layout.J) obj6), "Supporting")) {
                break;
            }
            i20++;
            i16 = i5;
            size6 = i21;
        }
        androidx.compose.ui.layout.J j7 = (androidx.compose.ui.layout.J) obj6;
        int iX = j7 != null ? j7.X(androidx.compose.ui.unit.a.j(j)) : 0;
        int iMax5 = Math.max((wB5 != null ? wB5.b : 0) / 2, m.m0(a0.b));
        long jA2 = androidx.compose.ui.unit.a.a(L5.o(i15, (i5 - iMax5) - iX, j), 0, 0, 0, 0, 11);
        int size7 = list2.size();
        int i22 = 0;
        while (i22 < size7) {
            androidx.compose.ui.layout.J j8 = (androidx.compose.ui.layout.J) list2.get(i22);
            int i23 = i22;
            int i24 = size7;
            if (Intrinsics.b(AbstractC0897s.h(j8), "TextField")) {
                androidx.compose.ui.layout.W wB6 = j8.B(jA2);
                long jA3 = androidx.compose.ui.unit.a.a(jA2, 0, 0, 0, 0, 14);
                int size8 = list2.size();
                int i25 = 0;
                while (true) {
                    if (i25 >= size8) {
                        obj7 = null;
                        break;
                    }
                    obj7 = list2.get(i25);
                    int i26 = size8;
                    int i27 = i25;
                    if (Intrinsics.b(AbstractC0897s.h((androidx.compose.ui.layout.J) obj7), "Hint")) {
                        break;
                    }
                    i25 = i27 + 1;
                    size8 = i26;
                }
                androidx.compose.ui.layout.J j9 = (androidx.compose.ui.layout.J) obj7;
                androidx.compose.ui.layout.W wB7 = j9 != null ? j9.B(jA3) : null;
                int iMax6 = Math.max(iMax4, Math.max(wB6.b, wB7 != null ? wB7.b : 0) + iMax5 + iM0);
                androidx.compose.ui.layout.W w2 = w;
                int iE = AbstractC0587a3.e(wB4 != null ? wB4.a : 0, w != null ? w2.a : 0, wB2 != null ? wB2.a : 0, wB3 != null ? wB3.a : 0, wB6.a, wB5 != null ? wB5.a : 0, wB7 != null ? wB7.a : 0, c0599c3.c, j, m.a(), c0599c3.d);
                androidx.compose.ui.layout.W wB8 = j7 != null ? j7.B(androidx.compose.ui.unit.a.a(L5.p(jA, 0, -iMax6, i), 0, iE, 0, 0, 9)) : null;
                int i28 = wB8 != null ? wB8.b : 0;
                int iD2 = AbstractC0587a3.d(wB4 != null ? wB4.b : 0, w2 != null ? w2.b : 0, wB2 != null ? wB2.b : 0, wB3 != null ? wB3.b : 0, wB6.b, wB5 != null ? wB5.b : 0, wB7 != null ? wB7.b : 0, wB8 != null ? wB8.b : 0, c0599c3.c, j, m.a(), c0599c3.d);
                int i29 = iD2 - i28;
                int size9 = list2.size();
                int i30 = 0;
                while (i30 < size9) {
                    androidx.compose.ui.layout.J j10 = (androidx.compose.ui.layout.J) list2.get(i30);
                    int i31 = iD2;
                    if (Intrinsics.b(AbstractC0897s.h(j10), "Container")) {
                        return m.n0(iE, i31, kotlin.collections.V.c(), new C0593b3(i31, iE, wB4, w2, wB2, wB3, wB6, wB5, wB7, j10.B(L5.a(iE != Integer.MAX_VALUE ? iE : 0, iE, i29 != Integer.MAX_VALUE ? i29 : 0, i29)), wB8, c0599c3, m));
                    }
                    iD2 = i31;
                    i30++;
                    wB4 = wB4;
                    wB5 = wB5;
                    c0599c3 = this;
                    list2 = list;
                }
                throw new NoSuchElementException("Collection contains no element matching the predicate.");
            }
            i22 = i23 + 1;
            wB4 = wB4;
            wB5 = wB5;
            c0599c3 = this;
            size7 = i24;
            jA2 = jA2;
            list2 = list;
        }
        throw new NoSuchElementException("Collection contains no element matching the predicate.");
    }

    @Override // androidx.compose.ui.layout.K
    public final int minIntrinsicHeight(InterfaceC0894o interfaceC0894o, List list, int i) {
        return a(interfaceC0894o, list, i, C0602d0.z);
    }

    @Override // androidx.compose.ui.layout.K
    public final int minIntrinsicWidth(InterfaceC0894o interfaceC0894o, List list, int i) {
        return b(interfaceC0894o, list, i, C0602d0.A);
    }
}
