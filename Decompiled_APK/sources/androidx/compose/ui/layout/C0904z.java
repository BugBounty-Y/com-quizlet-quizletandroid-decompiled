package androidx.compose.ui.layout;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.ui.layout.z, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0904z implements f0, M {
    public final /* synthetic */ B a;
    public final /* synthetic */ G b;

    public C0904z(G g) {
        this.b = g;
        this.a = g.h;
    }

    @Override // androidx.compose.ui.unit.b
    public final long K(float f) {
        return this.a.K(f);
    }

    @Override // androidx.compose.ui.unit.b
    public final float O(int i) {
        return this.a.O(i);
    }

    @Override // androidx.compose.ui.unit.b
    public final float R(float f) {
        return f / this.a.a();
    }

    @Override // androidx.compose.ui.unit.b
    public final float Z() {
        return this.a.c;
    }

    @Override // androidx.compose.ui.unit.b
    public final float a() {
        return this.a.b;
    }

    @Override // androidx.compose.ui.layout.InterfaceC0894o
    public final boolean a0() {
        return this.a.a0();
    }

    @Override // androidx.compose.ui.unit.b
    public final float c0(float f) {
        return this.a.a() * f;
    }

    @Override // androidx.compose.ui.layout.InterfaceC0894o
    public final androidx.compose.ui.unit.k getLayoutDirection() {
        return this.a.a;
    }

    @Override // androidx.compose.ui.unit.b
    public final int j0(long j) {
        return this.a.j0(j);
    }

    @Override // androidx.compose.ui.unit.b
    public final int m0(float f) {
        return this.a.m0(f);
    }

    @Override // androidx.compose.ui.layout.f0
    public final List n(Object obj, Function2 function2) {
        G g = this.b;
        androidx.compose.ui.node.E e = (androidx.compose.ui.node.E) g.g.get(obj);
        List listM = e != null ? e.m() : null;
        if (listM != null) {
            return listM;
        }
        androidx.compose.runtime.collection.b bVar = g.m;
        int i = bVar.c;
        int i2 = g.e;
        if (i < i2) {
            throw new IllegalArgumentException("Error: currentPostLookaheadIndex cannot be greater than the size of thepostLookaheadComposedSlotIds list.");
        }
        if (i == i2) {
            bVar.b(obj);
        } else {
            Object[] objArr = bVar.a;
            Object obj2 = objArr[i2];
            objArr[i2] = obj;
        }
        g.e++;
        HashMap map = g.j;
        if (!map.containsKey(obj)) {
            g.l.put(obj, g.g(obj, function2));
            androidx.compose.ui.node.E e2 = g.a;
            if (e2.x.c == 3) {
                e2.Q(true);
            } else {
                androidx.compose.ui.node.E.R(e2, true, 6);
            }
        }
        androidx.compose.ui.node.E e3 = (androidx.compose.ui.node.E) map.get(obj);
        if (e3 == null) {
            return kotlin.collections.K.a;
        }
        List listY0 = e3.x.r.y0();
        androidx.collection.E e4 = (androidx.collection.E) listY0;
        int i3 = ((androidx.compose.runtime.collection.b) e4.b).c;
        for (int i4 = 0; i4 < i3; i4++) {
            ((androidx.compose.ui.node.K) e4.get(i4)).H.b = true;
        }
        return listY0;
    }

    @Override // androidx.compose.ui.layout.M
    public final L n0(int i, int i2, Map map, Function1 function1) {
        return this.a.v(i, i2, map, function1);
    }

    @Override // androidx.compose.ui.unit.b
    public final long q0(long j) {
        return this.a.q0(j);
    }

    @Override // androidx.compose.ui.unit.b
    public final long r(float f) {
        return this.a.r(f);
    }

    @Override // androidx.compose.ui.unit.b
    public final long s(long j) {
        return this.a.s(j);
    }

    @Override // androidx.compose.ui.layout.M
    public final L v(int i, int i2, Map map, Function1 function1) {
        return this.a.v(i, i2, map, function1);
    }

    @Override // androidx.compose.ui.unit.b
    public final float v0(long j) {
        return this.a.v0(j);
    }

    @Override // androidx.compose.ui.unit.b
    public final float y(long j) {
        return this.a.y(j);
    }
}
