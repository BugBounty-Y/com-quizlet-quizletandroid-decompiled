package androidx.compose.runtime.snapshots;

import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.collections.U;
import kotlin.jvm.internal.AbstractC4958q;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class n implements Set, kotlin.jvm.internal.markers.f {
    public final t a;
    public final /* synthetic */ int b;

    public n(t tVar, int i) {
        this.b = i;
        this.a = tVar;
    }

    private final boolean a(Collection collection) {
        androidx.compose.runtime.external.kotlinx.collections.immutable.e eVar;
        int i;
        h hVarK;
        boolean zD;
        Set setA0 = CollectionsKt.A0(collection);
        t tVar = this.a;
        boolean z = false;
        do {
            synchronized (r.b) {
                s sVar = tVar.a;
                Intrinsics.e(sVar, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
                s sVar2 = (s) m.i(sVar);
                eVar = sVar2.c;
                i = sVar2.d;
                Unit unit = Unit.a;
            }
            Intrinsics.d(eVar);
            androidx.compose.runtime.external.kotlinx.collections.immutable.d dVarBuilder = eVar.builder();
            Iterator it2 = tVar.b.iterator();
            while (((y) it2).hasNext()) {
                Map.Entry entry = (Map.Entry) ((y) it2).next();
                if (!setA0.contains(entry.getKey())) {
                    dVarBuilder.remove(entry.getKey());
                    z = true;
                }
            }
            Unit unit2 = Unit.a;
            androidx.compose.runtime.external.kotlinx.collections.immutable.e eVarBuild = dVarBuilder.build();
            if (Intrinsics.b(eVarBuild, eVar)) {
                break;
            }
            s sVar3 = tVar.a;
            Intrinsics.e(sVar3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
            synchronized (m.b) {
                hVarK = m.k();
                zD = t.d(tVar, (s) m.w(sVar3, tVar, hVarK), i, eVarBuild);
            }
            m.n(hVarK, tVar);
        } while (!zD);
        return z;
    }

    @Override // java.util.Set, java.util.Collection
    public final boolean add(Object obj) {
        switch (this.b) {
            case 0:
                r.h();
                throw null;
            case 1:
                r.h();
                throw null;
            default:
                r.h();
                throw null;
        }
    }

    @Override // java.util.Set, java.util.Collection
    public final boolean addAll(Collection collection) {
        switch (this.b) {
            case 0:
                r.h();
                throw null;
            case 1:
                r.h();
                throw null;
            default:
                r.h();
                throw null;
        }
    }

    @Override // java.util.Set, java.util.Collection
    public final void clear() {
        this.a.clear();
    }

    @Override // java.util.Set, java.util.Collection
    public final boolean contains(Object obj) {
        switch (this.b) {
            case 0:
                if (!(obj instanceof Map.Entry) || ((obj instanceof kotlin.jvm.internal.markers.a) && !(obj instanceof kotlin.jvm.internal.markers.d))) {
                    return false;
                }
                Map.Entry entry = (Map.Entry) obj;
                return Intrinsics.b(this.a.get(entry.getKey()), entry.getValue());
            case 1:
                return this.a.containsKey(obj);
            default:
                return this.a.containsValue(obj);
        }
    }

    @Override // java.util.Set, java.util.Collection
    public final boolean containsAll(Collection collection) {
        switch (this.b) {
            case 0:
                Collection collection2 = collection;
                if (!(collection2 instanceof Collection) || !collection2.isEmpty()) {
                    Iterator it2 = collection2.iterator();
                    while (it2.hasNext()) {
                        if (!contains((Map.Entry) it2.next())) {
                            break;
                        }
                    }
                    break;
                }
                break;
            case 1:
                Collection collection3 = collection;
                if (!(collection3 instanceof Collection) || !collection3.isEmpty()) {
                    Iterator it3 = collection3.iterator();
                    while (it3.hasNext()) {
                        if (!this.a.containsKey(it3.next())) {
                            break;
                        }
                    }
                    break;
                }
                break;
            default:
                Collection collection4 = collection;
                if (!(collection4 instanceof Collection) || !collection4.isEmpty()) {
                    Iterator it4 = collection4.iterator();
                    while (it4.hasNext()) {
                        if (!this.a.containsValue(it4.next())) {
                            break;
                        }
                    }
                    break;
                }
                break;
        }
        return true;
    }

    @Override // java.util.Set, java.util.Collection
    public final boolean isEmpty() {
        return this.a.isEmpty();
    }

    @Override // java.util.Set, java.util.Collection, java.lang.Iterable
    public final Iterator iterator() {
        switch (this.b) {
            case 0:
                t tVar = this.a;
                return new y(tVar, ((androidx.compose.runtime.external.kotlinx.collections.immutable.b) tVar.e().c.entrySet()).iterator(), 0);
            case 1:
                t tVar2 = this.a;
                return new y(tVar2, ((androidx.compose.runtime.external.kotlinx.collections.immutable.b) tVar2.e().c.entrySet()).iterator(), 1);
            default:
                t tVar3 = this.a;
                return new y(tVar3, ((androidx.compose.runtime.external.kotlinx.collections.immutable.b) tVar3.e().c.entrySet()).iterator(), 2);
        }
    }

    @Override // java.util.Set, java.util.Collection
    public final boolean remove(Object obj) {
        Object next;
        switch (this.b) {
            case 0:
                if ((obj instanceof Map.Entry) && (!(obj instanceof kotlin.jvm.internal.markers.a) || (obj instanceof kotlin.jvm.internal.markers.d))) {
                    if (this.a.remove(((Map.Entry) obj).getKey()) != null) {
                        break;
                    }
                }
                break;
            case 1:
                if (this.a.remove(obj) != null) {
                }
                break;
            default:
                t tVar = this.a;
                Iterator it2 = tVar.b.iterator();
                while (true) {
                    if (((y) it2).hasNext()) {
                        next = ((y) it2).next();
                        if (Intrinsics.b(((Map.Entry) next).getValue(), obj)) {
                        }
                    } else {
                        next = null;
                    }
                }
                Map.Entry entry = (Map.Entry) next;
                if (entry != null) {
                    tVar.remove(entry.getKey());
                    break;
                }
                break;
        }
        return true;
    }

    @Override // java.util.Set, java.util.Collection
    public final boolean removeAll(Collection collection) {
        androidx.compose.runtime.external.kotlinx.collections.immutable.e eVar;
        int i;
        h hVarK;
        boolean zD;
        boolean z = false;
        switch (this.b) {
            case 0:
                Iterator it2 = collection.iterator();
                while (true) {
                    boolean z2 = false;
                    while (it2.hasNext()) {
                        if (this.a.remove(((Map.Entry) it2.next()).getKey()) != null || z2) {
                            z2 = true;
                        }
                    }
                    return z2;
                    break;
                }
            case 1:
                Iterator it3 = collection.iterator();
                while (true) {
                    boolean z3 = false;
                    while (it3.hasNext()) {
                        if (this.a.remove(it3.next()) != null || z3) {
                            z3 = true;
                        }
                    }
                    return z3;
                    break;
                }
                break;
            default:
                Set setA0 = CollectionsKt.A0(collection);
                t tVar = this.a;
                do {
                    synchronized (r.b) {
                        s sVar = tVar.a;
                        Intrinsics.e(sVar, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
                        s sVar2 = (s) m.i(sVar);
                        eVar = sVar2.c;
                        i = sVar2.d;
                        Unit unit = Unit.a;
                    }
                    Intrinsics.d(eVar);
                    androidx.compose.runtime.external.kotlinx.collections.immutable.d dVarBuilder = eVar.builder();
                    Iterator it4 = tVar.b.iterator();
                    while (((y) it4).hasNext()) {
                        Map.Entry entry = (Map.Entry) ((y) it4).next();
                        if (setA0.contains(entry.getValue())) {
                            dVarBuilder.remove(entry.getKey());
                            z = true;
                        }
                    }
                    Unit unit2 = Unit.a;
                    androidx.compose.runtime.external.kotlinx.collections.immutable.e eVarBuild = dVarBuilder.build();
                    if (!Intrinsics.b(eVarBuild, eVar)) {
                        s sVar3 = tVar.a;
                        Intrinsics.e(sVar3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
                        synchronized (m.b) {
                            hVarK = m.k();
                            zD = t.d(tVar, (s) m.w(sVar3, tVar, hVarK), i, eVarBuild);
                        }
                        m.n(hVarK, tVar);
                    }
                    return z;
                } while (!zD);
                return z;
        }
    }

    @Override // java.util.Set, java.util.Collection
    public final boolean retainAll(Collection collection) {
        androidx.compose.runtime.external.kotlinx.collections.immutable.e eVar;
        int i;
        h hVarK;
        boolean zD;
        androidx.compose.runtime.external.kotlinx.collections.immutable.e eVar2;
        int i2;
        h hVarK2;
        boolean zD2;
        boolean z = false;
        switch (this.b) {
            case 0:
                Collection<Map.Entry> collection2 = collection;
                int iA = U.a(kotlin.collections.C.q(collection2, 10));
                if (iA < 16) {
                    iA = 16;
                }
                LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
                for (Map.Entry entry : collection2) {
                    linkedHashMap.put(entry.getKey(), entry.getValue());
                }
                t tVar = this.a;
                do {
                    synchronized (r.b) {
                        s sVar = tVar.a;
                        Intrinsics.e(sVar, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
                        s sVar2 = (s) m.i(sVar);
                        eVar = sVar2.c;
                        i = sVar2.d;
                        Unit unit = Unit.a;
                    }
                    Intrinsics.d(eVar);
                    androidx.compose.runtime.external.kotlinx.collections.immutable.d dVarBuilder = eVar.builder();
                    Iterator it2 = tVar.b.iterator();
                    while (((y) it2).hasNext()) {
                        Map.Entry entry2 = (Map.Entry) ((y) it2).next();
                        if (!linkedHashMap.containsKey(entry2.getKey()) || !Intrinsics.b(linkedHashMap.get(entry2.getKey()), entry2.getValue())) {
                            dVarBuilder.remove(entry2.getKey());
                            z = true;
                        }
                    }
                    Unit unit2 = Unit.a;
                    androidx.compose.runtime.external.kotlinx.collections.immutable.e eVarBuild = dVarBuilder.build();
                    if (!Intrinsics.b(eVarBuild, eVar)) {
                        s sVar3 = tVar.a;
                        Intrinsics.e(sVar3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
                        synchronized (m.b) {
                            hVarK = m.k();
                            zD = t.d(tVar, (s) m.w(sVar3, tVar, hVarK), i, eVarBuild);
                        }
                        m.n(hVarK, tVar);
                    }
                    return z;
                } while (!zD);
                return z;
            case 1:
                return a(collection);
            default:
                Set setA0 = CollectionsKt.A0(collection);
                t tVar2 = this.a;
                do {
                    synchronized (r.b) {
                        s sVar4 = tVar2.a;
                        Intrinsics.e(sVar4, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
                        s sVar5 = (s) m.i(sVar4);
                        eVar2 = sVar5.c;
                        i2 = sVar5.d;
                        Unit unit3 = Unit.a;
                    }
                    Intrinsics.d(eVar2);
                    androidx.compose.runtime.external.kotlinx.collections.immutable.d dVarBuilder2 = eVar2.builder();
                    Iterator it3 = tVar2.b.iterator();
                    while (((y) it3).hasNext()) {
                        Map.Entry entry3 = (Map.Entry) ((y) it3).next();
                        if (!setA0.contains(entry3.getValue())) {
                            dVarBuilder2.remove(entry3.getKey());
                            z = true;
                        }
                    }
                    Unit unit4 = Unit.a;
                    androidx.compose.runtime.external.kotlinx.collections.immutable.e eVarBuild2 = dVarBuilder2.build();
                    if (!Intrinsics.b(eVarBuild2, eVar2)) {
                        s sVar6 = tVar2.a;
                        Intrinsics.e(sVar6, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
                        synchronized (m.b) {
                            hVarK2 = m.k();
                            zD2 = t.d(tVar2, (s) m.w(sVar6, tVar2, hVarK2), i2, eVarBuild2);
                        }
                        m.n(hVarK2, tVar2);
                    }
                    return z;
                } while (!zD2);
                return z;
        }
    }

    @Override // java.util.Set, java.util.Collection
    public final int size() {
        return this.a.size();
    }

    @Override // java.util.Set, java.util.Collection
    public final Object[] toArray() {
        return AbstractC4958q.a(this);
    }

    @Override // java.util.Set, java.util.Collection
    public final Object[] toArray(Object[] objArr) {
        return AbstractC4958q.b(this, objArr);
    }
}
