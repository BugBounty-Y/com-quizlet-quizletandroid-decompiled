package androidx.compose.foundation.text;

import androidx.compose.animation.C0278e;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import java.util.ArrayList;
import java.util.List;
import kotlin.Pair;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class O0 implements androidx.compose.ui.layout.K {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;

    public /* synthetic */ O0(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // androidx.compose.ui.layout.K
    /* renamed from: measure-3p2s80s */
    public final androidx.compose.ui.layout.L mo1measure3p2s80s(androidx.compose.ui.layout.M m, List list, long j) {
        switch (this.a) {
            case 0:
                ArrayList arrayList = new ArrayList(list.size());
                int size = list.size();
                for (int i = 0; i < size; i++) {
                    Object obj = list.get(i);
                    if (!(((androidx.compose.ui.layout.J) obj).G() instanceof P0)) {
                        arrayList.add(obj);
                    }
                }
                List list2 = (List) ((Function0) this.c).invoke();
                ArrayList arrayList2 = null;
                if (list2 != null) {
                    ArrayList arrayList3 = new ArrayList(list2.size());
                    int size2 = list2.size();
                    for (int i2 = 0; i2 < size2; i2++) {
                        androidx.compose.ui.geometry.c cVar = (androidx.compose.ui.geometry.c) list2.get(i2);
                        Pair pair = cVar != null ? new Pair(((androidx.compose.ui.layout.J) arrayList.get(i2)).B(L5.b((int) Math.floor(cVar.e()), (int) Math.floor(cVar.d()), 5)), new androidx.compose.ui.unit.h(P5.b(Math.round(cVar.a), Math.round(cVar.b)))) : null;
                        if (pair != null) {
                            arrayList3.add(pair);
                        }
                    }
                    arrayList2 = arrayList3;
                }
                ArrayList arrayList4 = new ArrayList(list.size());
                int size3 = list.size();
                for (int i3 = 0; i3 < size3; i3++) {
                    Object obj2 = list.get(i3);
                    if (((androidx.compose.ui.layout.J) obj2).G() instanceof P0) {
                        arrayList4.add(obj2);
                    }
                }
                return m.n0(androidx.compose.ui.unit.a.h(j), androidx.compose.ui.unit.a.g(j), kotlin.collections.V.c(), new C0278e(25, arrayList2, AbstractC0484d0.n(arrayList4, (Function0) this.b)));
            default:
                ((androidx.compose.ui.window.u) this.b).setParentLayoutDirection((androidx.compose.ui.unit.k) this.c);
                return m.n0(0, 0, kotlin.collections.V.c(), androidx.compose.ui.window.c.d);
        }
    }
}
