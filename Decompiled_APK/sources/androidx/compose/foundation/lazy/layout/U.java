package androidx.compose.foundation.lazy.layout;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class U implements androidx.compose.ui.layout.M {
    public final M a;
    public final androidx.compose.ui.layout.f0 b;
    public final N c;
    public final HashMap d = new HashMap();

    public U(M m, androidx.compose.ui.layout.f0 f0Var) {
        this.a = m;
        this.b = f0Var;
        this.c = (N) m.b.invoke();
    }

    @Override // androidx.compose.ui.unit.b
    public final long K(float f) {
        return this.b.K(f);
    }

    @Override // androidx.compose.ui.unit.b
    public final float O(int i) {
        return this.b.O(i);
    }

    @Override // androidx.compose.ui.unit.b
    public final float R(float f) {
        return this.b.R(f);
    }

    @Override // androidx.compose.ui.unit.b
    public final float Z() {
        return this.b.Z();
    }

    @Override // androidx.compose.ui.unit.b
    public final float a() {
        return this.b.a();
    }

    @Override // androidx.compose.ui.layout.InterfaceC0894o
    public final boolean a0() {
        return this.b.a0();
    }

    public final List b(int i, long j) {
        HashMap map = this.d;
        List list = (List) map.get(Integer.valueOf(i));
        if (list != null) {
            return list;
        }
        N n = this.c;
        Object objB = n.b(i);
        List listN = this.b.n(objB, this.a.a(i, objB, n.c(i)));
        int size = listN.size();
        ArrayList arrayList = new ArrayList(size);
        for (int i2 = 0; i2 < size; i2++) {
            arrayList.add(((androidx.compose.ui.layout.J) listN.get(i2)).B(j));
        }
        map.put(Integer.valueOf(i), arrayList);
        return arrayList;
    }

    @Override // androidx.compose.ui.unit.b
    public final float c0(float f) {
        return this.b.c0(f);
    }

    @Override // androidx.compose.ui.layout.InterfaceC0894o
    public final androidx.compose.ui.unit.k getLayoutDirection() {
        return this.b.getLayoutDirection();
    }

    @Override // androidx.compose.ui.unit.b
    public final int j0(long j) {
        return this.b.j0(j);
    }

    @Override // androidx.compose.ui.unit.b
    public final int m0(float f) {
        return this.b.m0(f);
    }

    @Override // androidx.compose.ui.layout.M
    public final androidx.compose.ui.layout.L n0(int i, int i2, Map map, Function1 function1) {
        return this.b.n0(i, i2, map, function1);
    }

    @Override // androidx.compose.ui.unit.b
    public final long q0(long j) {
        return this.b.q0(j);
    }

    @Override // androidx.compose.ui.unit.b
    public final long r(float f) {
        return this.b.r(f);
    }

    @Override // androidx.compose.ui.unit.b
    public final long s(long j) {
        return this.b.s(j);
    }

    @Override // androidx.compose.ui.layout.M
    public final androidx.compose.ui.layout.L v(int i, int i2, Map map, Function1 function1) {
        return this.b.v(i, i2, map, function1);
    }

    @Override // androidx.compose.ui.unit.b
    public final float v0(long j) {
        return this.b.v0(j);
    }

    @Override // androidx.compose.ui.unit.b
    public final float y(long j) {
        return this.b.y(j);
    }
}
