package androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import kotlin.collections.AbstractC4916g;

/* loaded from: classes.dex */
public abstract class c extends AbstractC4916g implements androidx.compose.runtime.external.kotlinx.collections.immutable.c {
    @Override // java.util.Collection, java.util.List, androidx.compose.runtime.external.kotlinx.collections.immutable.c
    public androidx.compose.runtime.external.kotlinx.collections.immutable.c addAll(Collection collection) {
        g gVarBuilder = builder();
        gVarBuilder.addAll(collection);
        return gVarBuilder.e();
    }

    @Override // kotlin.collections.AbstractC4911b, java.util.Collection, java.util.List
    public final boolean contains(Object obj) {
        return indexOf(obj) != -1;
    }

    @Override // kotlin.collections.AbstractC4911b, java.util.Collection, java.util.List
    public final boolean containsAll(Collection collection) {
        Collection collection2 = collection;
        if ((collection2 instanceof Collection) && collection2.isEmpty()) {
            return true;
        }
        Iterator it2 = collection2.iterator();
        while (it2.hasNext()) {
            if (!contains(it2.next())) {
                return false;
            }
        }
        return true;
    }

    @Override // kotlin.collections.AbstractC4916g, java.util.Collection, java.lang.Iterable, java.util.List
    public final Iterator iterator() {
        return listIterator(0);
    }

    @Override // kotlin.collections.AbstractC4916g, java.util.List
    public final ListIterator listIterator() {
        return listIterator(0);
    }

    @Override // kotlin.collections.AbstractC4916g, java.util.List
    public final List subList(int i, int i2) {
        return new androidx.compose.runtime.external.kotlinx.collections.immutable.a(this, i, i2);
    }
}
