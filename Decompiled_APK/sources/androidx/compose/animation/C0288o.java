package androidx.compose.animation;

import androidx.compose.runtime.L0;
import androidx.compose.ui.layout.InterfaceC0894o;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;

/* renamed from: androidx.compose.animation.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0288o implements androidx.compose.ui.layout.K {
    public final C0292t a;

    public C0288o(C0292t c0292t) {
        this.a = c0292t;
    }

    @Override // androidx.compose.ui.layout.K
    public final int maxIntrinsicHeight(InterfaceC0894o interfaceC0894o, List list, int i) {
        Integer numValueOf;
        if (list.isEmpty()) {
            numValueOf = null;
        } else {
            numValueOf = Integer.valueOf(((androidx.compose.ui.layout.J) list.get(0)).b(i));
            int i2 = kotlin.collections.B.i(list);
            int i3 = 1;
            if (1 <= i2) {
                while (true) {
                    Integer numValueOf2 = Integer.valueOf(((androidx.compose.ui.layout.J) list.get(i3)).b(i));
                    if (numValueOf2.compareTo(numValueOf) > 0) {
                        numValueOf = numValueOf2;
                    }
                    if (i3 == i2) {
                        break;
                    }
                    i3++;
                }
            }
        }
        if (numValueOf != null) {
            return numValueOf.intValue();
        }
        return 0;
    }

    @Override // androidx.compose.ui.layout.K
    public final int maxIntrinsicWidth(InterfaceC0894o interfaceC0894o, List list, int i) {
        Integer numValueOf;
        if (list.isEmpty()) {
            numValueOf = null;
        } else {
            numValueOf = Integer.valueOf(((androidx.compose.ui.layout.J) list.get(0)).z(i));
            int i2 = kotlin.collections.B.i(list);
            int i3 = 1;
            if (1 <= i2) {
                while (true) {
                    Integer numValueOf2 = Integer.valueOf(((androidx.compose.ui.layout.J) list.get(i3)).z(i));
                    if (numValueOf2.compareTo(numValueOf) > 0) {
                        numValueOf = numValueOf2;
                    }
                    if (i3 == i2) {
                        break;
                    }
                    i3++;
                }
            }
        }
        if (numValueOf != null) {
            return numValueOf.intValue();
        }
        return 0;
    }

    @Override // androidx.compose.ui.layout.K
    /* renamed from: measure-3p2s80s, reason: not valid java name */
    public final androidx.compose.ui.layout.L mo1measure3p2s80s(androidx.compose.ui.layout.M m, List list, long j) {
        androidx.compose.ui.layout.W w;
        androidx.compose.ui.layout.W w2;
        int i;
        int size = list.size();
        androidx.compose.ui.layout.W[] wArr = new androidx.compose.ui.layout.W[size];
        int size2 = list.size();
        long j2 = 0;
        int i2 = 0;
        int i3 = 0;
        while (true) {
            w = null;
            if (i3 >= size2) {
                break;
            }
            androidx.compose.ui.layout.J j3 = (androidx.compose.ui.layout.J) list.get(i3);
            Object objG = j3.G();
            C0290q c0290q = objG instanceof C0290q ? (C0290q) objG : null;
            if (c0290q != null && ((Boolean) ((L0) c0290q.b).getValue()).booleanValue()) {
                androidx.compose.ui.layout.W wB = j3.B(j);
                long jA = R5.a(wB.a, wB.b);
                Unit unit = Unit.a;
                wArr[i3] = wB;
                j2 = jA;
            }
            i3++;
        }
        int size3 = list.size();
        for (int i4 = 0; i4 < size3; i4++) {
            androidx.compose.ui.layout.J j4 = (androidx.compose.ui.layout.J) list.get(i4);
            if (wArr[i4] == null) {
                wArr[i4] = j4.B(j);
            }
        }
        if (m.a0()) {
            i = (int) (j2 >> 32);
        } else {
            if (size == 0) {
                w2 = null;
            } else {
                w2 = wArr[0];
                Intrinsics.checkNotNullParameter(wArr, "<this>");
                int i5 = size - 1;
                if (i5 != 0) {
                    int i6 = w2 != null ? w2.a : 0;
                    kotlin.ranges.i it2 = new IntRange(1, i5, 1).iterator();
                    while (it2.c) {
                        androidx.compose.ui.layout.W w3 = wArr[it2.nextInt()];
                        int i7 = w3 != null ? w3.a : 0;
                        if (i6 < i7) {
                            w2 = w3;
                            i6 = i7;
                        }
                    }
                }
            }
            i = w2 != null ? w2.a : 0;
        }
        if (m.a0()) {
            i2 = (int) (4294967295L & j2);
        } else {
            if (size != 0) {
                w = wArr[0];
                Intrinsics.checkNotNullParameter(wArr, "<this>");
                int i8 = size - 1;
                if (i8 != 0) {
                    int i9 = w != null ? w.b : 0;
                    kotlin.ranges.i it3 = new IntRange(1, i8, 1).iterator();
                    while (it3.c) {
                        androidx.compose.ui.layout.W w4 = wArr[it3.nextInt()];
                        int i10 = w4 != null ? w4.b : 0;
                        if (i9 < i10) {
                            w = w4;
                            i9 = i10;
                        }
                    }
                }
            }
            if (w != null) {
                i2 = w.b;
            }
        }
        if (!m.a0()) {
            ((L0) this.a.c).setValue(new androidx.compose.ui.unit.j(R5.a(i, i2)));
        }
        return m.n0(i, i2, kotlin.collections.V.c(), new C0287n(wArr, this, i, i2));
    }

    @Override // androidx.compose.ui.layout.K
    public final int minIntrinsicHeight(InterfaceC0894o interfaceC0894o, List list, int i) {
        Integer numValueOf;
        if (list.isEmpty()) {
            numValueOf = null;
        } else {
            numValueOf = Integer.valueOf(((androidx.compose.ui.layout.J) list.get(0)).X(i));
            int i2 = kotlin.collections.B.i(list);
            int i3 = 1;
            if (1 <= i2) {
                while (true) {
                    Integer numValueOf2 = Integer.valueOf(((androidx.compose.ui.layout.J) list.get(i3)).X(i));
                    if (numValueOf2.compareTo(numValueOf) > 0) {
                        numValueOf = numValueOf2;
                    }
                    if (i3 == i2) {
                        break;
                    }
                    i3++;
                }
            }
        }
        if (numValueOf != null) {
            return numValueOf.intValue();
        }
        return 0;
    }

    @Override // androidx.compose.ui.layout.K
    public final int minIntrinsicWidth(InterfaceC0894o interfaceC0894o, List list, int i) {
        Integer numValueOf;
        if (list.isEmpty()) {
            numValueOf = null;
        } else {
            numValueOf = Integer.valueOf(((androidx.compose.ui.layout.J) list.get(0)).x(i));
            int i2 = kotlin.collections.B.i(list);
            int i3 = 1;
            if (1 <= i2) {
                while (true) {
                    Integer numValueOf2 = Integer.valueOf(((androidx.compose.ui.layout.J) list.get(i3)).x(i));
                    if (numValueOf2.compareTo(numValueOf) > 0) {
                        numValueOf = numValueOf2;
                    }
                    if (i3 == i2) {
                        break;
                    }
                    i3++;
                }
            }
        }
        if (numValueOf != null) {
            return numValueOf.intValue();
        }
        return 0;
    }
}
