package androidx.compose.foundation.text.selection;

import androidx.compose.animation.C0293u;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes.dex */
public final class d0 implements androidx.compose.ui.layout.K {
    public static final d0 a = new d0();

    @Override // androidx.compose.ui.layout.K
    /* renamed from: measure-3p2s80s */
    public final androidx.compose.ui.layout.L mo1measure3p2s80s(androidx.compose.ui.layout.M m, List list, long j) {
        ArrayList arrayList = new ArrayList(list.size());
        int size = list.size();
        Integer numValueOf = 0;
        for (int i = 0; i < size; i++) {
            arrayList.add(((androidx.compose.ui.layout.J) list.get(i)).B(j));
        }
        int size2 = arrayList.size();
        Integer numValueOf2 = numValueOf;
        for (int i2 = 0; i2 < size2; i2++) {
            numValueOf2 = Integer.valueOf(Math.max(numValueOf2.intValue(), ((androidx.compose.ui.layout.W) arrayList.get(i2)).a));
        }
        int iIntValue = numValueOf2.intValue();
        int size3 = arrayList.size();
        for (int i3 = 0; i3 < size3; i3++) {
            numValueOf = Integer.valueOf(Math.max(numValueOf.intValue(), ((androidx.compose.ui.layout.W) arrayList.get(i3)).b));
        }
        return m.n0(iIntValue, numValueOf.intValue(), kotlin.collections.V.c(), new C0293u(2, arrayList));
    }
}
