package com.google.android.gms.internal.ads;

import java.util.Collection;
import java.util.ConcurrentModificationException;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;

/* loaded from: classes2.dex */
public class It implements Iterator {
    public final /* synthetic */ int a = 0;
    public final Iterator b;
    public Object c;
    public final /* synthetic */ Object d;

    public It(Kt kt, Iterator it2) {
        this.b = it2;
        this.d = kt;
    }

    public void a() {
        Rt rt = (Rt) this.d;
        rt.b();
        if (rt.c != ((Collection) this.c)) {
            throw new ConcurrentModificationException();
        }
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        switch (this.a) {
            case 0:
                break;
            case 1:
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
                return ((Jt) this.d).a(entry);
            case 1:
                Map.Entry entry2 = (Map.Entry) this.b.next();
                this.c = entry2;
                return entry2.getKey();
            default:
                a();
                return this.b.next();
        }
    }

    @Override // java.util.Iterator
    public final void remove() {
        switch (this.a) {
            case 0:
                AbstractC1981ds.L("no calls to next() since the last call to remove()", ((Collection) this.c) != null);
                this.b.remove();
                ((C2845xu) ((Jt) this.d).e).e -= ((Collection) this.c).size();
                ((Collection) this.c).clear();
                this.c = null;
                break;
            case 1:
                AbstractC1981ds.L("no calls to next() since the last call to remove()", ((Map.Entry) this.c) != null);
                Collection collection = (Collection) ((Map.Entry) this.c).getValue();
                this.b.remove();
                ((Kt) this.d).c.e -= collection.size();
                collection.clear();
                this.c = null;
                break;
            default:
                this.b.remove();
                Rt rt = (Rt) this.d;
                C2845xu c2845xu = (C2845xu) rt.f;
                c2845xu.e--;
                rt.c();
                break;
        }
    }

    public It(Rt rt, ListIterator listIterator) {
        this.d = rt;
        this.c = rt.c;
        this.b = listIterator;
    }

    public It(Jt jt) {
        this.d = jt;
        this.b = jt.d.entrySet().iterator();
    }

    public It(Rt rt) {
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
