package com.google.common.collect;

import java.util.AbstractCollection;
import java.util.Iterator;
import java.util.List;

/* renamed from: com.google.common.collect.d, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3921d extends AbstractCollection {
    public final List a;
    public final com.quizlet.baserecyclerview.decoration.a b;

    public C3921d(List list, com.quizlet.baserecyclerview.decoration.a aVar) {
        list.getClass();
        this.a = list;
        this.b = aVar;
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public final void clear() {
        this.a.clear();
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public final boolean isEmpty() {
        return this.a.isEmpty();
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable
    public final Iterator iterator() {
        Iterator it2 = this.a.iterator();
        com.quizlet.baserecyclerview.decoration.a aVar = this.b;
        aVar.getClass();
        return new q(it2, aVar);
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public final int size() {
        return this.a.size();
    }
}
