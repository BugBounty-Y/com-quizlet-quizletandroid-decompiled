package androidx.compose.runtime;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class V implements kotlin.coroutines.l, M0 {
    public static final /* synthetic */ V b = new V(0);
    public static final V c = new V(1);
    public static final V d = new V(2);
    public static final V e = new V(3);
    public static final V f = new V(4);
    public final /* synthetic */ int a;

    public /* synthetic */ V(int i) {
        this.a = i;
    }

    public static final void b(V v) {
        kotlinx.coroutines.flow.s0 s0Var;
        androidx.compose.runtime.external.kotlinx.collections.immutable.f fVar;
        androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.persistentOrderedSet.b bVar;
        kotlinx.coroutines.flow.s0 s0Var2 = C0832v0.y;
        do {
            s0Var = C0832v0.y;
            fVar = (androidx.compose.runtime.external.kotlinx.collections.immutable.f) s0Var.getValue();
            bVar = (androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.persistentOrderedSet.b) fVar;
            androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.c cVarH = bVar.d;
            androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.persistentOrderedSet.a aVar = (androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.persistentOrderedSet.a) cVarH.get(v);
            if (aVar != null) {
                int iHashCode = v != null ? v.hashCode() : 0;
                androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.n nVar = cVarH.b;
                androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.n nVarV = nVar.v(iHashCode, v, 0);
                if (nVar != nVarV) {
                    cVarH = nVarV == null ? androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.c.d : new androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.c(nVarV, cVarH.c - 1);
                }
                androidx.compose.runtime.external.kotlinx.collections.immutable.internal.b bVar2 = androidx.compose.runtime.external.kotlinx.collections.immutable.internal.b.a;
                Object obj = aVar.a;
                boolean z = obj != bVar2;
                Object obj2 = aVar.b;
                if (z) {
                    Object obj3 = cVarH.get(obj);
                    Intrinsics.d(obj3);
                    cVarH = cVarH.h(obj, new androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.persistentOrderedSet.a(((androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.persistentOrderedSet.a) obj3).a, obj2));
                }
                if (obj2 != bVar2) {
                    Object obj4 = cVarH.get(obj2);
                    Intrinsics.d(obj4);
                    cVarH = cVarH.h(obj2, new androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.persistentOrderedSet.a(obj, ((androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.persistentOrderedSet.a) obj4).b));
                }
                Object obj5 = obj != bVar2 ? bVar.b : obj2;
                if (obj2 != bVar2) {
                    obj = bVar.c;
                }
                bVar = new androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.persistentOrderedSet.b(obj5, obj, cVarH);
            }
            if (fVar == bVar) {
                return;
            }
        } while (!s0Var.k(fVar, bVar));
    }

    @Override // androidx.compose.runtime.M0
    public boolean a(Object obj, Object obj2) {
        switch (this.a) {
            case 1:
                return false;
            case 2:
                return obj == obj2;
            default:
                return Intrinsics.b(obj, obj2);
        }
    }

    public String toString() {
        switch (this.a) {
            case 1:
                return "NeverEqualPolicy";
            case 2:
                return "ReferentialEqualityPolicy";
            case 3:
            case 5:
            default:
                return super.toString();
            case 4:
                return "StructuralEqualityPolicy";
            case 6:
                return "Empty";
        }
    }
}
