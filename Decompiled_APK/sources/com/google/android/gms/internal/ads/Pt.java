package com.google.android.gms.internal.ads;

import java.util.Comparator;
import java.util.SortedMap;
import java.util.SortedSet;

/* loaded from: classes2.dex */
public class Pt extends Kt implements SortedSet {
    public final /* synthetic */ C2845xu d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Pt(C2845xu c2845xu, SortedMap sortedMap) {
        super(c2845xu, sortedMap);
        this.d = c2845xu;
    }

    public SortedMap a() {
        return (SortedMap) this.b;
    }

    @Override // java.util.SortedSet
    public final Comparator comparator() {
        return a().comparator();
    }

    @Override // java.util.SortedSet
    public final Object first() {
        return a().firstKey();
    }

    public SortedSet headSet(Object obj) {
        return new Pt(this.d, a().headMap(obj));
    }

    @Override // java.util.SortedSet
    public final Object last() {
        return a().lastKey();
    }

    public SortedSet subSet(Object obj, Object obj2) {
        return new Pt(this.d, a().subMap(obj, obj2));
    }

    public SortedSet tailSet(Object obj) {
        return new Pt(this.d, a().tailMap(obj));
    }
}
