package androidx.compose.animation;

import androidx.compose.runtime.L0;
import androidx.compose.ui.layout.InterfaceC0894o;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import java.util.ArrayList;
import java.util.List;

/* renamed from: androidx.compose.animation.v, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0294v implements androidx.compose.ui.layout.K {
    public final G a;
    public boolean b;

    public C0294v(G g) {
        this.a = g;
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
    /* renamed from: measure-3p2s80s */
    public final androidx.compose.ui.layout.L mo1measure3p2s80s(androidx.compose.ui.layout.M m, List list, long j) {
        Object obj;
        ArrayList arrayList = new ArrayList(list.size());
        int size = list.size();
        for (int i = 0; i < size; i++) {
            arrayList.add(((androidx.compose.ui.layout.J) list.get(i)).B(j));
        }
        Object obj2 = null;
        if (arrayList.isEmpty()) {
            obj = null;
        } else {
            obj = arrayList.get(0);
            int i2 = ((androidx.compose.ui.layout.W) obj).a;
            int i3 = kotlin.collections.B.i(arrayList);
            if (1 <= i3) {
                int i4 = 1;
                while (true) {
                    Object obj3 = arrayList.get(i4);
                    int i5 = ((androidx.compose.ui.layout.W) obj3).a;
                    if (i2 < i5) {
                        obj = obj3;
                        i2 = i5;
                    }
                    if (i4 == i3) {
                        break;
                    }
                    i4++;
                }
            }
        }
        androidx.compose.ui.layout.W w = (androidx.compose.ui.layout.W) obj;
        int i6 = w != null ? w.a : 0;
        if (!arrayList.isEmpty()) {
            obj2 = arrayList.get(0);
            int i7 = ((androidx.compose.ui.layout.W) obj2).b;
            int i8 = kotlin.collections.B.i(arrayList);
            if (1 <= i8) {
                int i9 = 1;
                while (true) {
                    Object obj4 = arrayList.get(i9);
                    int i10 = ((androidx.compose.ui.layout.W) obj4).b;
                    if (i7 < i10) {
                        obj2 = obj4;
                        i7 = i10;
                    }
                    if (i9 == i8) {
                        break;
                    }
                    i9++;
                }
            }
        }
        androidx.compose.ui.layout.W w2 = (androidx.compose.ui.layout.W) obj2;
        int i11 = w2 != null ? w2.b : 0;
        boolean zA0 = m.a0();
        G g = this.a;
        if (zA0) {
            this.b = true;
            ((L0) g.a).setValue(new androidx.compose.ui.unit.j(R5.a(i6, i11)));
        } else if (!this.b) {
            ((L0) g.a).setValue(new androidx.compose.ui.unit.j(R5.a(i6, i11)));
        }
        return m.n0(i6, i11, kotlin.collections.V.c(), new C0293u(0, arrayList));
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
