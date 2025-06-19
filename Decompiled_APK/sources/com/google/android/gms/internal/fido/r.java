package com.google.android.gms.internal.fido;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.Iterator;
import java.util.Map;
import java.util.NavigableMap;
import java.util.NavigableSet;
import java.util.Objects;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;

/* loaded from: classes2.dex */
public final class r extends AbstractC2950n implements NavigableMap {
    public static final r f;
    public final transient C2961z c;
    public final transient AbstractC2949m d;
    public final transient r e;

    static {
        C2961z c2961zS = AbstractC2954s.s(C2957v.b);
        C2945i c2945i = AbstractC2949m.b;
        f = new r(c2961zS, C2959x.e, null);
    }

    public r(C2961z c2961z, AbstractC2949m abstractC2949m, r rVar) {
        this.c = c2961z;
        this.d = abstractC2949m;
        this.e = rVar;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static r b(TreeMap treeMap) {
        C2957v c2957v = C2957v.b;
        Comparator comparator = treeMap.comparator();
        int i = 1;
        boolean zEquals = comparator == null ? true : c2957v.equals(comparator);
        Set setEntrySet = treeMap.entrySet();
        Map.Entry[] entryArr = AbstractC2950n.b;
        if (!(setEntrySet instanceof Collection)) {
            Iterator it2 = setEntrySet.iterator();
            ArrayList arrayList = new ArrayList();
            it2.getClass();
            while (it2.hasNext()) {
                arrayList.add(it2.next());
            }
            setEntrySet = arrayList;
        }
        Map.Entry[] entryArr2 = (Map.Entry[]) setEntrySet.toArray(entryArr);
        int length = entryArr2.length;
        if (length == 0) {
            return d(c2957v);
        }
        int i2 = 0;
        if (length == 1) {
            Map.Entry entry = entryArr2[0];
            Objects.requireNonNull(entry);
            Object key = entry.getKey();
            Object value = entry.getValue();
            Object[] objArr = {key};
            for (int i3 = 0; i3 < 1; i3++) {
                if (objArr[i3] == null) {
                    throw new NullPointerException(android.support.v4.media.session.a.f(i3, "at index "));
                }
            }
            C2961z c2961z = new C2961z(AbstractC2949m.k(1, objArr), c2957v);
            Object[] objArr2 = {value};
            while (i2 < 1) {
                if (objArr2[i2] == null) {
                    throw new NullPointerException(android.support.v4.media.session.a.f(i2, "at index "));
                }
                i2++;
            }
            return new r(c2961z, AbstractC2949m.k(1, objArr2), null);
        }
        Object[] objArr3 = new Object[length];
        Object[] objArr4 = new Object[length];
        if (zEquals) {
            while (i2 < length) {
                Map.Entry entry2 = entryArr2[i2];
                Objects.requireNonNull(entry2);
                Object key2 = entry2.getKey();
                Object value2 = entry2.getValue();
                AbstractC2937a.f(key2, value2);
                objArr3[i2] = key2;
                objArr4[i2] = value2;
                i2++;
            }
        } else {
            Arrays.sort(entryArr2, 0, length, new androidx.constraintlayout.core.e(26));
            Map.Entry entry3 = entryArr2[0];
            Objects.requireNonNull(entry3);
            Object key3 = entry3.getKey();
            objArr3[0] = key3;
            Object value3 = entry3.getValue();
            objArr4[0] = value3;
            AbstractC2937a.f(objArr3[0], value3);
            while (i < length) {
                Map.Entry entry4 = entryArr2[i - 1];
                Objects.requireNonNull(entry4);
                Map.Entry entry5 = entryArr2[i];
                Objects.requireNonNull(entry5);
                Object key4 = entry5.getKey();
                Object value4 = entry5.getValue();
                AbstractC2937a.f(key4, value4);
                objArr3[i] = key4;
                objArr4[i] = value4;
                if (c2957v.compare(key3, key4) == 0) {
                    throw new IllegalArgumentException(android.support.v4.media.session.a.m("Multiple entries with same key: ", String.valueOf(entry4), " and ", String.valueOf(entry5)));
                }
                i++;
                key3 = key4;
            }
        }
        return new r(new C2961z(AbstractC2949m.k(length, objArr3), c2957v), AbstractC2949m.k(length, objArr4), null);
    }

    public static r d(Comparator comparator) {
        if (C2957v.b.equals(comparator)) {
            return f;
        }
        C2961z c2961zS = AbstractC2954s.s(comparator);
        C2945i c2945i = AbstractC2949m.b;
        return new r(c2961zS, C2959x.e, null);
    }

    @Override // java.util.NavigableMap
    public final Map.Entry ceilingEntry(Object obj) {
        return tailMap(obj, true).firstEntry();
    }

    @Override // java.util.NavigableMap
    public final Object ceilingKey(Object obj) {
        Map.Entry entryCeilingEntry = ceilingEntry(obj);
        if (entryCeilingEntry == null) {
            return null;
        }
        return entryCeilingEntry.getKey();
    }

    @Override // java.util.SortedMap
    public final Comparator comparator() {
        return this.c.d;
    }

    @Override // java.util.NavigableMap
    public final /* synthetic */ NavigableSet descendingKeySet() {
        return this.c.descendingSet();
    }

    @Override // java.util.NavigableMap
    public final /* bridge */ /* synthetic */ NavigableMap descendingMap() {
        r rVar = this.e;
        if (rVar != null) {
            return rVar;
        }
        boolean zIsEmpty = isEmpty();
        C2961z c2961z = this.c;
        if (!zIsEmpty) {
            return new r((C2961z) c2961z.descendingSet(), this.d.h(), this);
        }
        Comparator comparator = c2961z.d;
        return d((comparator instanceof AbstractC2958w ? (AbstractC2958w) comparator : new C2943g(comparator)).a());
    }

    @Override // java.util.NavigableMap
    /* renamed from: e, reason: merged with bridge method [inline-methods] */
    public final r headMap(Object obj, boolean z) {
        obj.getClass();
        return h(0, this.c.t(obj, z));
    }

    @Override // java.util.NavigableMap
    /* renamed from: f, reason: merged with bridge method [inline-methods] */
    public final r subMap(Object obj, boolean z, Object obj2, boolean z2) {
        obj.getClass();
        obj2.getClass();
        if (this.c.d.compare(obj, obj2) <= 0) {
            return headMap(obj2, z2).tailMap(obj, z);
        }
        throw new IllegalArgumentException(AbstractC2937a.d("expected fromKey <= toKey but %s > %s", obj, obj2));
    }

    @Override // java.util.NavigableMap
    public final Map.Entry firstEntry() {
        if (isEmpty()) {
            return null;
        }
        return (Map.Entry) entrySet().k().get(0);
    }

    @Override // java.util.SortedMap
    public final Object firstKey() {
        return this.c.first();
    }

    @Override // java.util.NavigableMap
    public final Map.Entry floorEntry(Object obj) {
        return headMap(obj, true).lastEntry();
    }

    @Override // java.util.NavigableMap
    public final Object floorKey(Object obj) {
        Map.Entry entryFloorEntry = floorEntry(obj);
        if (entryFloorEntry == null) {
            return null;
        }
        return entryFloorEntry.getKey();
    }

    @Override // java.util.NavigableMap
    /* renamed from: g, reason: merged with bridge method [inline-methods] */
    public final r tailMap(Object obj, boolean z) {
        obj.getClass();
        return h(this.c.u(obj, z), this.d.size());
    }

    /* JADX WARN: Removed duplicated region for block: B:4:0x0005  */
    @Override // com.google.android.gms.internal.fido.AbstractC2950n, java.util.Map
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object get(java.lang.Object r4) {
        /*
            r3 = this;
            com.google.android.gms.internal.fido.z r0 = r3.c
            r1 = -1
            if (r4 != 0) goto L7
        L5:
            r4 = r1
            goto L12
        L7:
            com.google.android.gms.internal.fido.m r2 = r0.f     // Catch: java.lang.ClassCastException -> L5
            java.util.Comparator r0 = r0.d     // Catch: java.lang.ClassCastException -> L5
            int r4 = java.util.Collections.binarySearch(r2, r4, r0)     // Catch: java.lang.ClassCastException -> L5
            if (r4 >= 0) goto L12
            goto L5
        L12:
            if (r4 != r1) goto L16
            r4 = 0
            return r4
        L16:
            com.google.android.gms.internal.fido.m r0 = r3.d
            java.lang.Object r4 = r0.get(r4)
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.fido.r.get(java.lang.Object):java.lang.Object");
    }

    public final r h(int i, int i2) {
        AbstractC2949m abstractC2949m = this.d;
        if (i == 0) {
            if (i2 == abstractC2949m.size()) {
                return this;
            }
            i = 0;
        }
        C2961z c2961z = this.c;
        return i == i2 ? d(c2961z.d) : new r(c2961z.v(i, i2), abstractC2949m.subList(i, i2), null);
    }

    @Override // java.util.NavigableMap, java.util.SortedMap
    public final /* synthetic */ SortedMap headMap(Object obj) {
        return headMap(obj, false);
    }

    @Override // java.util.NavigableMap
    public final Map.Entry higherEntry(Object obj) {
        return tailMap(obj, false).firstEntry();
    }

    @Override // java.util.NavigableMap
    public final Object higherKey(Object obj) {
        Map.Entry entryHigherEntry = higherEntry(obj);
        if (entryHigherEntry == null) {
            return null;
        }
        return entryHigherEntry.getKey();
    }

    @Override // java.util.Map, java.util.SortedMap
    public final /* synthetic */ Set keySet() {
        return this.c;
    }

    @Override // java.util.NavigableMap
    public final Map.Entry lastEntry() {
        if (isEmpty()) {
            return null;
        }
        return (Map.Entry) entrySet().k().get(this.d.size() - 1);
    }

    @Override // java.util.SortedMap
    public final Object lastKey() {
        return this.c.last();
    }

    @Override // java.util.NavigableMap
    public final Map.Entry lowerEntry(Object obj) {
        return headMap(obj, false).lastEntry();
    }

    @Override // java.util.NavigableMap
    public final Object lowerKey(Object obj) {
        Map.Entry entryLowerEntry = lowerEntry(obj);
        if (entryLowerEntry == null) {
            return null;
        }
        return entryLowerEntry.getKey();
    }

    @Override // java.util.NavigableMap
    public final /* synthetic */ NavigableSet navigableKeySet() {
        return this.c;
    }

    @Override // java.util.NavigableMap
    public final Map.Entry pollFirstEntry() {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.NavigableMap
    public final Map.Entry pollLastEntry() {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.Map
    public final int size() {
        return this.d.size();
    }

    @Override // java.util.NavigableMap, java.util.SortedMap
    public final /* bridge */ /* synthetic */ SortedMap subMap(Object obj, Object obj2) {
        return subMap(obj, true, obj2, false);
    }

    @Override // java.util.NavigableMap, java.util.SortedMap
    public final /* synthetic */ SortedMap tailMap(Object obj) {
        return tailMap(obj, true);
    }

    @Override // java.util.Map, java.util.SortedMap
    public final /* synthetic */ Collection values() {
        return this.d;
    }
}
