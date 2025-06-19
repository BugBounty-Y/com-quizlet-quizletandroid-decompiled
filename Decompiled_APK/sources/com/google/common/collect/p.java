package com.google.common.collect;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.common.base.Predicate;
import java.util.Iterator;
import java.util.NoSuchElementException;

/* loaded from: classes2.dex */
public final class p extends com.google.android.gms.internal.common.g {
    public int b;
    public Object c;
    public final /* synthetic */ Iterator d;
    public final /* synthetic */ Predicate e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public p(Iterator it2, Predicate predicate) {
        super(5);
        this.d = it2;
        this.e = predicate;
        this.b = 2;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        Object next;
        int i = this.b;
        if (i == 4) {
            throw new IllegalStateException();
        }
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return true;
        }
        if (iK == 2) {
            return false;
        }
        this.b = 4;
        while (true) {
            Iterator it2 = this.d;
            if (!it2.hasNext()) {
                this.b = 3;
                next = null;
                break;
            }
            next = it2.next();
            if (this.e.apply(next)) {
                break;
            }
        }
        this.c = next;
        if (this.b == 3) {
            return false;
        }
        this.b = 1;
        return true;
    }

    @Override // java.util.Iterator
    public final Object next() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }
        this.b = 2;
        Object obj = this.c;
        this.c = null;
        return obj;
    }
}
