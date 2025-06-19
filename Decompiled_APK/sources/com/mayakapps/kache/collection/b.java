package com.mayakapps.kache.collection;

import java.util.Collection;
import java.util.Iterator;
import kotlin.collections.AbstractC4925p;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b extends AbstractC4925p {
    public final /* synthetic */ c b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ boolean d;

    public b(c cVar, boolean z, boolean z2) {
        this.b = cVar;
        this.c = z;
        this.d = z2;
    }

    @Override // kotlin.collections.AbstractC4911b
    public final int a() {
        return this.b.e;
    }

    @Override // kotlin.collections.AbstractC4911b, java.util.Collection, java.util.List
    public final boolean contains(Object obj) {
        return this.b.e(obj);
    }

    @Override // kotlin.collections.AbstractC4911b, java.util.Collection, java.util.List
    public final boolean containsAll(Collection elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        Collection collection = elements;
        if (collection.isEmpty()) {
            return true;
        }
        Iterator it2 = collection.iterator();
        while (it2.hasNext()) {
            if (!this.b.e(it2.next())) {
                return false;
            }
        }
        return true;
    }

    @Override // kotlin.collections.AbstractC4911b, java.util.Collection
    public final boolean isEmpty() {
        return this.b.e == 0;
    }

    @Override // kotlin.collections.AbstractC4925p, java.util.Collection, java.lang.Iterable, java.util.Set
    public final Iterator iterator() {
        c cVar = this.b;
        boolean z = this.c;
        androidx.compose.ui.text.android.selection.f fVar = cVar.i;
        androidx.compose.ui.text.android.selection.f fVar2 = cVar.h;
        if (z) {
            if (fVar2 == null) {
                Intrinsics.d(fVar);
            } else {
                fVar = fVar2;
            }
        } else if (fVar == null) {
            Intrinsics.d(fVar2);
            fVar = fVar2;
        }
        return new a(this.d, cVar, fVar);
    }
}
