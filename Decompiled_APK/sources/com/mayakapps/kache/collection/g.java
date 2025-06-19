package com.mayakapps.kache.collection;

import androidx.compose.ui.graphics.vector.G;
import java.util.Collection;
import java.util.Iterator;
import kotlin.collections.AbstractC4919j;
import kotlin.collections.AbstractC4925p;
import kotlin.jvm.internal.Intrinsics;
import kotlin.sequences.j;

/* loaded from: classes2.dex */
public final class g extends AbstractC4925p {
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;

    public /* synthetic */ g(Object obj, int i) {
        this.b = i;
        this.c = obj;
    }

    @Override // kotlin.collections.AbstractC4911b
    public final int a() {
        switch (this.b) {
            case 0:
                return ((d) this.c).e;
            default:
                return ((AbstractC4919j) this.c).d();
        }
    }

    @Override // kotlin.collections.AbstractC4911b, java.util.Collection, java.util.List
    public final boolean contains(Object obj) {
        switch (this.b) {
            case 0:
                return ((d) this.c).e(obj);
            default:
                return ((AbstractC4919j) this.c).containsKey(obj);
        }
    }

    @Override // kotlin.collections.AbstractC4911b, java.util.Collection, java.util.List
    public boolean containsAll(Collection elements) {
        switch (this.b) {
            case 0:
                Intrinsics.checkNotNullParameter(elements, "elements");
                Collection collection = elements;
                if (collection.isEmpty()) {
                    return true;
                }
                Iterator it2 = collection.iterator();
                while (it2.hasNext()) {
                    if (!((d) this.c).e(it2.next())) {
                        return false;
                    }
                }
                return true;
            default:
                return super.containsAll(elements);
        }
    }

    @Override // kotlin.collections.AbstractC4911b, java.util.Collection
    public boolean isEmpty() {
        switch (this.b) {
            case 0:
                return ((d) this.c).e == 0;
            default:
                return super.isEmpty();
        }
    }

    @Override // kotlin.collections.AbstractC4925p, java.util.Collection, java.lang.Iterable, java.util.Set
    public final Iterator iterator() {
        switch (this.b) {
            case 0:
                return j.a(new f((d) this.c, null));
            default:
                return new G(((AbstractC4919j) this.c).a().iterator(), 1);
        }
    }
}
