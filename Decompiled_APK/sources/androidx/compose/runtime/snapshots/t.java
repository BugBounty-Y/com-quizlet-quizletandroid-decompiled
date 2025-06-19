package androidx.compose.runtime.snapshots;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class t implements z, Map, kotlin.jvm.internal.markers.e {
    public s a;
    public final n b;
    public final n c;
    public final n d;

    public t() {
        androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.c cVar = androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.c.d;
        h hVarK = m.k();
        s sVar = new s(hVarK.g(), cVar);
        if (!(hVarK instanceof C0823c)) {
            sVar.b = new s(1, cVar);
        }
        this.a = sVar;
        this.b = new n(this, 0);
        this.c = new n(this, 1);
        this.d = new n(this, 2);
    }

    public static final boolean d(t tVar, s sVar, int i, androidx.compose.runtime.external.kotlinx.collections.immutable.e eVar) {
        boolean z;
        tVar.getClass();
        synchronized (r.b) {
            int i2 = sVar.d;
            if (i2 == i) {
                sVar.c = eVar;
                z = true;
                sVar.d = i2 + 1;
            } else {
                z = false;
            }
        }
        return z;
    }

    @Override // androidx.compose.runtime.snapshots.z
    public final void a(B b) {
        Intrinsics.e(b, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
        this.a = (s) b;
    }

    @Override // androidx.compose.runtime.snapshots.z
    public final B b() {
        return this.a;
    }

    @Override // java.util.Map
    public final void clear() {
        h hVarK;
        s sVar = this.a;
        Intrinsics.e(sVar, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
        s sVar2 = (s) m.i(sVar);
        androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.c cVar = androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.c.d;
        if (cVar != sVar2.c) {
            s sVar3 = this.a;
            Intrinsics.e(sVar3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
            synchronized (m.b) {
                hVarK = m.k();
                s sVar4 = (s) m.w(sVar3, this, hVarK);
                synchronized (r.b) {
                    sVar4.c = cVar;
                    sVar4.d++;
                }
            }
            m.n(hVarK, this);
        }
    }

    @Override // java.util.Map
    public final boolean containsKey(Object obj) {
        return e().c.containsKey(obj);
    }

    @Override // java.util.Map
    public final boolean containsValue(Object obj) {
        return e().c.containsValue(obj);
    }

    public final s e() {
        s sVar = this.a;
        Intrinsics.e(sVar, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
        return (s) m.t(sVar, this);
    }

    @Override // java.util.Map
    public final Set entrySet() {
        return this.b;
    }

    @Override // java.util.Map
    public final Object get(Object obj) {
        return e().c.get(obj);
    }

    @Override // java.util.Map
    public final boolean isEmpty() {
        return e().c.isEmpty();
    }

    @Override // java.util.Map
    public final Set keySet() {
        return this.c;
    }

    @Override // java.util.Map
    public final Object put(Object obj, Object obj2) {
        androidx.compose.runtime.external.kotlinx.collections.immutable.e eVar;
        int i;
        Object objPut;
        h hVarK;
        boolean zD;
        do {
            synchronized (r.b) {
                s sVar = this.a;
                Intrinsics.e(sVar, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
                s sVar2 = (s) m.i(sVar);
                eVar = sVar2.c;
                i = sVar2.d;
                Unit unit = Unit.a;
            }
            Intrinsics.d(eVar);
            androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.e eVar2 = (androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.e) eVar.builder();
            objPut = eVar2.put(obj, obj2);
            androidx.compose.runtime.external.kotlinx.collections.immutable.e eVarBuild = eVar2.build();
            if (Intrinsics.b(eVarBuild, eVar)) {
                break;
            }
            s sVar3 = this.a;
            Intrinsics.e(sVar3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
            synchronized (m.b) {
                hVarK = m.k();
                zD = d(this, (s) m.w(sVar3, this, hVarK), i, eVarBuild);
            }
            m.n(hVarK, this);
        } while (!zD);
        return objPut;
    }

    @Override // java.util.Map
    public final void putAll(Map map) {
        androidx.compose.runtime.external.kotlinx.collections.immutable.e eVar;
        int i;
        h hVarK;
        boolean zD;
        do {
            synchronized (r.b) {
                s sVar = this.a;
                Intrinsics.e(sVar, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
                s sVar2 = (s) m.i(sVar);
                eVar = sVar2.c;
                i = sVar2.d;
                Unit unit = Unit.a;
            }
            Intrinsics.d(eVar);
            androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.e eVar2 = (androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.e) eVar.builder();
            eVar2.putAll(map);
            androidx.compose.runtime.external.kotlinx.collections.immutable.e eVarBuild = eVar2.build();
            if (Intrinsics.b(eVarBuild, eVar)) {
                return;
            }
            s sVar3 = this.a;
            Intrinsics.e(sVar3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
            synchronized (m.b) {
                hVarK = m.k();
                zD = d(this, (s) m.w(sVar3, this, hVarK), i, eVarBuild);
            }
            m.n(hVarK, this);
        } while (!zD);
    }

    @Override // java.util.Map
    public final Object remove(Object obj) {
        androidx.compose.runtime.external.kotlinx.collections.immutable.e eVar;
        int i;
        Object objRemove;
        h hVarK;
        boolean zD;
        do {
            synchronized (r.b) {
                s sVar = this.a;
                Intrinsics.e(sVar, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
                s sVar2 = (s) m.i(sVar);
                eVar = sVar2.c;
                i = sVar2.d;
                Unit unit = Unit.a;
            }
            Intrinsics.d(eVar);
            androidx.compose.runtime.external.kotlinx.collections.immutable.d dVarBuilder = eVar.builder();
            objRemove = dVarBuilder.remove(obj);
            androidx.compose.runtime.external.kotlinx.collections.immutable.e eVarBuild = dVarBuilder.build();
            if (Intrinsics.b(eVarBuild, eVar)) {
                break;
            }
            s sVar3 = this.a;
            Intrinsics.e(sVar3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
            synchronized (m.b) {
                hVarK = m.k();
                zD = d(this, (s) m.w(sVar3, this, hVarK), i, eVarBuild);
            }
            m.n(hVarK, this);
        } while (!zD);
        return objRemove;
    }

    @Override // java.util.Map
    public final int size() {
        return e().c.size();
    }

    public final String toString() {
        s sVar = this.a;
        Intrinsics.e(sVar, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
        return "SnapshotStateMap(value=" + ((s) m.i(sVar)).c + ")@" + hashCode();
    }

    @Override // java.util.Map
    public final Collection values() {
        return this.d;
    }
}
