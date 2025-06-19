package androidx.compose.ui.layout;

import androidx.compose.animation.C0293u;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes.dex */
public final class Z extends androidx.compose.ui.node.C {
    public static final Z b = new Z("Undefined intrinsics block and it is required");

    @Override // androidx.compose.ui.layout.K
    /* renamed from: measure-3p2s80s */
    public final L mo1measure3p2s80s(M m, List list, long j) {
        if (list.isEmpty()) {
            return m.n0(androidx.compose.ui.unit.a.j(j), androidx.compose.ui.unit.a.i(j), kotlin.collections.V.c(), X.c);
        }
        if (list.size() == 1) {
            W wB = ((J) list.get(0)).B(j);
            return m.n0(L5.l(wB.a, j), L5.k(wB.b, j), kotlin.collections.V.c(), new androidx.compose.animation.C(wB, 14));
        }
        ArrayList arrayList = new ArrayList(list.size());
        int size = list.size();
        for (int i = 0; i < size; i++) {
            arrayList.add(((J) list.get(i)).B(j));
        }
        int size2 = arrayList.size();
        int iMax = 0;
        int iMax2 = 0;
        for (int i2 = 0; i2 < size2; i2++) {
            W w = (W) arrayList.get(i2);
            iMax = Math.max(w.a, iMax);
            iMax2 = Math.max(w.b, iMax2);
        }
        return m.n0(L5.l(iMax, j), L5.k(iMax2, j), kotlin.collections.V.c(), new C0293u(3, arrayList));
    }
}
