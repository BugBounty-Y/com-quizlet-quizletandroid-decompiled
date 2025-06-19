package androidx.glance;

import androidx.compose.runtime.AbstractC0772a;
import androidx.glance.appwidget.B0;
import java.util.ArrayList;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b extends AbstractC0772a {
    public final int d;

    public b(B0 b0) {
        super(b0);
        this.d = b0.a;
    }

    @Override // androidx.compose.runtime.InterfaceC0790d
    public final /* bridge */ /* synthetic */ void c(int i, Object obj) {
    }

    @Override // androidx.compose.runtime.InterfaceC0790d
    public final void e(int i, int i2, int i3) {
        ArrayList arrayListO = o();
        int i4 = i > i2 ? i2 : i2 - i3;
        if (i3 != 1) {
            List listSubList = arrayListO.subList(i, i3 + i);
            ArrayList arrayListY0 = CollectionsKt.y0(listSubList);
            listSubList.clear();
            arrayListO.addAll(i4, arrayListY0);
            return;
        }
        if (i == i2 + 1 || i == i2 - 1) {
            arrayListO.set(i, arrayListO.set(i2, arrayListO.get(i)));
        } else {
            arrayListO.add(i4, arrayListO.remove(i));
        }
    }

    @Override // androidx.compose.runtime.InterfaceC0790d
    public final void f(int i, int i2) {
        ArrayList arrayListO = o();
        if (i2 == 1) {
            arrayListO.remove(i);
        } else {
            arrayListO.subList(i, i2 + i).clear();
        }
    }

    @Override // androidx.compose.runtime.InterfaceC0790d
    public final void i(int i, Object obj) {
        k kVar = (k) obj;
        Object obj2 = this.b;
        Intrinsics.e(obj2, "null cannot be cast to non-null type androidx.glance.EmittableWithChildren");
        int i2 = ((m) obj2).a;
        if (i2 > 0) {
            if (kVar instanceof m) {
                m mVar = (m) kVar;
                mVar.a = mVar.b ? this.d : i2 - 1;
            }
            o().add(i, kVar);
            return;
        }
        StringBuilder sb = new StringBuilder("Too many embedded views for the current surface. The maximum depth is: ");
        Object obj3 = this.a;
        Intrinsics.e(obj3, "null cannot be cast to non-null type androidx.glance.EmittableWithChildren");
        sb.append(((m) obj3).a);
        throw new IllegalArgumentException(sb.toString().toString());
    }

    @Override // androidx.compose.runtime.AbstractC0772a
    public final void m() {
        Object obj = this.a;
        Intrinsics.e(obj, "null cannot be cast to non-null type androidx.glance.EmittableWithChildren");
        ((m) obj).c.clear();
    }

    public final ArrayList o() {
        k kVar = (k) this.b;
        if (kVar instanceof m) {
            return ((m) kVar).c;
        }
        throw new IllegalStateException("Current node cannot accept children");
    }
}
