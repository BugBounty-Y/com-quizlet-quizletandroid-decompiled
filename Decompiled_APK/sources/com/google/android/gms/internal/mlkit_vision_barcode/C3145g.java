package com.google.android.gms.internal.mlkit_vision_barcode;

import com.google.android.gms.internal.ads.Jt;
import com.google.android.gms.internal.ads.Rt;
import java.util.Collection;
import java.util.ConcurrentModificationException;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.RandomAccess;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.g, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public class C3145g implements Iterator {
    public final /* synthetic */ int a = 0;
    public final Iterator b;
    public Collection c;
    public final /* synthetic */ Object d;

    public C3145g(Rt rt, ListIterator listIterator) {
        this.d = rt;
        this.c = rt.c;
        this.b = listIterator;
    }

    public void a() {
        Rt rt = (Rt) this.d;
        rt.b();
        if (rt.c != this.c) {
            throw new ConcurrentModificationException();
        }
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        switch (this.a) {
            case 0:
                break;
            default:
                a();
                break;
        }
        return this.b.hasNext();
    }

    @Override // java.util.Iterator
    public final Object next() {
        switch (this.a) {
            case 0:
                Map.Entry entry = (Map.Entry) this.b.next();
                this.c = (Collection) entry.getValue();
                Object key = entry.getKey();
                Collection collection = (Collection) entry.getValue();
                C3199m c3199m = (C3199m) ((Jt) this.d).e;
                List list = (List) collection;
                return new C3260t(key, list instanceof RandomAccess ? new C3163i(c3199m, key, list, null) : new Rt(c3199m, key, list, (Rt) null));
            default:
                a();
                return this.b.next();
        }
    }

    @Override // java.util.Iterator
    public final void remove() {
        switch (this.a) {
            case 0:
                if (!(this.c != null)) {
                    throw new IllegalStateException("no calls to next() since the last call to remove()");
                }
                this.b.remove();
                this.c.size();
                this.c.clear();
                this.c = null;
                return;
            default:
                this.b.remove();
                Rt rt = (Rt) this.d;
                ((C3199m) rt.f).getClass();
                rt.c();
                return;
        }
    }

    public C3145g(Jt jt) {
        this.d = jt;
        this.b = ((r) jt.d).entrySet().iterator();
    }

    public C3145g(Rt rt) {
        Iterator it2;
        this.d = rt;
        Collection collection = rt.c;
        this.c = collection;
        if (collection instanceof List) {
            it2 = ((List) collection).listIterator();
        } else {
            it2 = collection.iterator();
        }
        this.b = it2;
    }
}
