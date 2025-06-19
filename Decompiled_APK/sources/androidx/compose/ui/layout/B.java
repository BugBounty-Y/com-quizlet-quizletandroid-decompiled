package androidx.compose.ui.layout;

import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class B implements f0 {
    public androidx.compose.ui.unit.k a = androidx.compose.ui.unit.k.b;
    public float b;
    public float c;
    public final /* synthetic */ G d;

    public B(G g) {
        this.d = g;
    }

    @Override // androidx.compose.ui.unit.b
    public final float Z() {
        return this.c;
    }

    @Override // androidx.compose.ui.unit.b
    public final float a() {
        return this.b;
    }

    @Override // androidx.compose.ui.layout.InterfaceC0894o
    public final boolean a0() {
        int i = this.d.a.x.c;
        return i == 4 || i == 2;
    }

    @Override // androidx.compose.ui.layout.InterfaceC0894o
    public final androidx.compose.ui.unit.k getLayoutDirection() {
        return this.a;
    }

    @Override // androidx.compose.ui.layout.f0
    public final List n(Object obj, Function2 function2) {
        androidx.compose.ui.node.E e;
        G g = this.d;
        g.e();
        androidx.compose.ui.node.E e2 = g.a;
        int i = e2.x.c;
        if (!(i == 1 || i == 3 || i == 2 || i == 4)) {
            W4.f("subcompose can only be used inside the measure or layout blocks");
            throw null;
        }
        HashMap map = g.g;
        Object obj2 = map.get(obj);
        Object obj3 = obj2;
        if (obj2 == null) {
            androidx.compose.ui.node.E e3 = (androidx.compose.ui.node.E) g.j.remove(obj);
            if (e3 != null) {
                int i2 = g.o;
                if (i2 <= 0) {
                    W4.f("Check failed.");
                    throw null;
                }
                g.o = i2 - 1;
                e = e3;
            } else {
                androidx.compose.ui.node.E eJ = g.j(obj);
                if (eJ == null) {
                    int i3 = g.d;
                    androidx.compose.ui.node.E e4 = new androidx.compose.ui.node.E(2);
                    e2.l = true;
                    e2.y(i3, e4);
                    e2.l = false;
                    e = e4;
                } else {
                    e = eJ;
                }
            }
            map.put(obj, e);
            obj3 = e;
        }
        androidx.compose.ui.node.E e5 = (androidx.compose.ui.node.E) obj3;
        if (CollectionsKt.O(g.d, e2.p()) != e5) {
            int iK = ((androidx.compose.runtime.collection.b) ((androidx.collection.E) e2.p()).b).k(e5);
            int i4 = g.d;
            if (iK < i4) {
                throw new IllegalArgumentException(("Key \"" + obj + "\" was already used. If you are using LazyColumn/Row please make sure you provide a unique key for each item.").toString());
            }
            if (i4 != iK) {
                e2.l = true;
                e2.I(iK, i4, 1);
                e2.l = false;
            }
        }
        g.d++;
        g.h(e5, obj, function2);
        return (i == 1 || i == 3) ? e5.m() : e5.l();
    }

    @Override // androidx.compose.ui.layout.M
    public final L v(int i, int i2, Map map, Function1 function1) {
        if ((i & (-16777216)) == 0 && ((-16777216) & i2) == 0) {
            return new A(i, i2, map, this, this.d, function1);
        }
        W4.f("Size(" + i + " x " + i2 + ") is out of range. Each dimension must be between 0 and 16777215.");
        throw null;
    }
}
