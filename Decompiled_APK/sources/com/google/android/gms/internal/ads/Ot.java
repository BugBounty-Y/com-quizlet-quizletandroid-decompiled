package com.google.android.gms.internal.ads;

import java.util.Comparator;
import java.util.SortedMap;
import java.util.SortedSet;

/* loaded from: classes2.dex */
public class Ot extends Jt implements SortedMap {
    public SortedSet f;
    public final /* synthetic */ C2845xu g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Ot(C2845xu c2845xu, SortedMap sortedMap) {
        super(c2845xu, sortedMap, 0);
        this.g = c2845xu;
    }

    public SortedMap b() {
        return (SortedMap) this.d;
    }

    @Override // java.util.SortedMap
    public final Comparator comparator() {
        return b().comparator();
    }

    public SortedSet d() {
        return new Pt(this.g, b());
    }

    @Override // com.google.android.gms.internal.ads.Jt, java.util.AbstractMap, java.util.Map
    /* renamed from: e, reason: merged with bridge method [inline-methods] */
    public SortedSet keySet() {
        SortedSet sortedSet = this.f;
        if (sortedSet != null) {
            return sortedSet;
        }
        SortedSet sortedSetD = d();
        this.f = sortedSetD;
        return sortedSetD;
    }

    @Override // java.util.SortedMap
    public final Object firstKey() {
        return b().firstKey();
    }

    public SortedMap headMap(Object obj) {
        return new Ot(this.g, b().headMap(obj));
    }

    @Override // java.util.SortedMap
    public final Object lastKey() {
        return b().lastKey();
    }

    public SortedMap subMap(Object obj, Object obj2) {
        return new Ot(this.g, b().subMap(obj, obj2));
    }

    public SortedMap tailMap(Object obj) {
        return new Ot(this.g, b().tailMap(obj));
    }
}
