package com.google.android.gms.internal.ads;

import com.google.android.gms.internal.mlkit_vision_barcode.C3145g;
import com.google.android.gms.internal.mlkit_vision_barcode.C3163i;
import com.google.android.gms.internal.mlkit_vision_barcode.C3172j;
import com.google.android.gms.internal.mlkit_vision_barcode.C3199m;
import java.io.Serializable;
import java.util.AbstractCollection;
import java.util.Collection;
import java.util.ConcurrentModificationException;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.RandomAccess;

/* loaded from: classes2.dex */
public class Rt extends AbstractCollection implements List {
    public final /* synthetic */ int a = 0;
    public final Object b;
    public Collection c;
    public final Collection d;
    public final AbstractCollection e;
    public final /* synthetic */ Serializable f;
    public final /* synthetic */ Serializable g;

    public Rt(C2845xu c2845xu, Object obj, List list, Rt rt) {
        this.g = c2845xu;
        this.f = c2845xu;
        this.b = obj;
        this.c = list;
        this.e = rt;
        this.d = rt == null ? null : rt.c;
    }

    public final void a() {
        switch (this.a) {
            case 0:
                Rt rt = (Rt) this.e;
                if (rt == null) {
                    ((C2845xu) this.f).d.put(this.b, this.c);
                    break;
                } else {
                    rt.a();
                    break;
                }
            default:
                Rt rt2 = (Rt) this.e;
                if (rt2 == null) {
                    ((C3199m) this.f).c.put(this.b, this.c);
                    break;
                } else {
                    rt2.a();
                    break;
                }
        }
    }

    @Override // java.util.List
    public final void add(int i, Object obj) {
        switch (this.a) {
            case 0:
                b();
                boolean zIsEmpty = this.c.isEmpty();
                ((List) this.c).add(i, obj);
                ((C2845xu) this.g).e++;
                if (zIsEmpty) {
                    a();
                    break;
                }
                break;
            default:
                b();
                boolean zIsEmpty2 = this.c.isEmpty();
                ((List) this.c).add(i, obj);
                ((C3199m) this.g).getClass();
                if (zIsEmpty2) {
                    a();
                    break;
                }
                break;
        }
    }

    @Override // java.util.List
    public final boolean addAll(int i, Collection collection) {
        switch (this.a) {
            case 0:
                if (!collection.isEmpty()) {
                    int size = size();
                    boolean zAddAll = ((List) this.c).addAll(i, collection);
                    if (zAddAll) {
                        ((C2845xu) this.g).e += this.c.size() - size;
                        if (size == 0) {
                            a();
                            break;
                        }
                    }
                }
                break;
            default:
                if (!collection.isEmpty()) {
                    int size2 = size();
                    boolean zAddAll2 = ((List) this.c).addAll(i, collection);
                    if (zAddAll2) {
                        this.c.size();
                        ((C3199m) this.g).getClass();
                        if (size2 == 0) {
                            a();
                            break;
                        }
                    }
                }
                break;
        }
        return true;
    }

    public final void b() {
        Collection collection;
        Collection collection2;
        switch (this.a) {
            case 0:
                Rt rt = (Rt) this.e;
                if (rt != null) {
                    rt.b();
                    if (rt.c != this.d) {
                        throw new ConcurrentModificationException();
                    }
                    return;
                } else {
                    if (!this.c.isEmpty() || (collection = (Collection) ((C2845xu) this.f).d.get(this.b)) == null) {
                        return;
                    }
                    this.c = collection;
                    return;
                }
            default:
                Rt rt2 = (Rt) this.e;
                if (rt2 != null) {
                    rt2.b();
                    if (rt2.c != this.d) {
                        throw new ConcurrentModificationException();
                    }
                    return;
                } else {
                    if (!this.c.isEmpty() || (collection2 = (Collection) ((C3199m) this.f).c.get(this.b)) == null) {
                        return;
                    }
                    this.c = collection2;
                    return;
                }
        }
    }

    public final void c() {
        switch (this.a) {
            case 0:
                Rt rt = (Rt) this.e;
                if (rt == null) {
                    if (this.c.isEmpty()) {
                        ((C2845xu) this.f).d.remove(this.b);
                        break;
                    }
                } else {
                    rt.c();
                    break;
                }
                break;
            default:
                Rt rt2 = (Rt) this.e;
                if (rt2 == null) {
                    if (this.c.isEmpty()) {
                        ((C3199m) this.f).c.remove(this.b);
                        break;
                    }
                } else {
                    rt2.c();
                    break;
                }
                break;
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final void clear() {
        switch (this.a) {
            case 0:
                int size = size();
                if (size != 0) {
                    this.c.clear();
                    ((C2845xu) this.f).e -= size;
                    c();
                    break;
                }
                break;
            default:
                if (size() != 0) {
                    this.c.clear();
                    ((C3199m) this.f).getClass();
                    c();
                    break;
                }
                break;
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean contains(Object obj) {
        switch (this.a) {
            case 0:
                b();
                break;
            default:
                b();
                break;
        }
        return this.c.contains(obj);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean containsAll(Collection collection) {
        switch (this.a) {
            case 0:
                b();
                break;
            default:
                b();
                break;
        }
        return this.c.containsAll(collection);
    }

    @Override // java.util.Collection, java.util.List
    public final boolean equals(Object obj) {
        switch (this.a) {
            case 0:
                if (obj != this) {
                    b();
                    break;
                }
                break;
            default:
                if (obj != this) {
                    b();
                    break;
                }
                break;
        }
        return this.c.equals(obj);
    }

    @Override // java.util.List
    public final Object get(int i) {
        switch (this.a) {
            case 0:
                b();
                break;
            default:
                b();
                break;
        }
        return ((List) this.c).get(i);
    }

    @Override // java.util.Collection, java.util.List
    public final int hashCode() {
        switch (this.a) {
            case 0:
                b();
                break;
            default:
                b();
                break;
        }
        return this.c.hashCode();
    }

    @Override // java.util.List
    public final int indexOf(Object obj) {
        switch (this.a) {
            case 0:
                b();
                break;
            default:
                b();
                break;
        }
        return ((List) this.c).indexOf(obj);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.List
    public final Iterator iterator() {
        switch (this.a) {
            case 0:
                b();
                return new It(this);
            default:
                b();
                return new C3145g(this);
        }
    }

    @Override // java.util.List
    public final int lastIndexOf(Object obj) {
        switch (this.a) {
            case 0:
                b();
                break;
            default:
                b();
                break;
        }
        return ((List) this.c).lastIndexOf(obj);
    }

    @Override // java.util.List
    public final ListIterator listIterator() {
        switch (this.a) {
            case 0:
                b();
                return new Qt(this);
            default:
                b();
                return new C3172j(this);
        }
    }

    @Override // java.util.List
    public final Object remove(int i) {
        switch (this.a) {
            case 0:
                b();
                Object objRemove = ((List) this.c).remove(i);
                C2845xu c2845xu = (C2845xu) this.g;
                c2845xu.e--;
                c();
                return objRemove;
            default:
                b();
                Object objRemove2 = ((List) this.c).remove(i);
                ((C3199m) this.g).getClass();
                c();
                return objRemove2;
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean removeAll(Collection collection) {
        switch (this.a) {
            case 0:
                if (collection.isEmpty()) {
                    return false;
                }
                int size = size();
                boolean zRemoveAll = this.c.removeAll(collection);
                if (!zRemoveAll) {
                    return zRemoveAll;
                }
                ((C2845xu) this.f).e += this.c.size() - size;
                c();
                return zRemoveAll;
            default:
                if (collection.isEmpty()) {
                    return false;
                }
                size();
                boolean zRemoveAll2 = this.c.removeAll(collection);
                if (!zRemoveAll2) {
                    return zRemoveAll2;
                }
                this.c.size();
                ((C3199m) this.f).getClass();
                c();
                return zRemoveAll2;
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean retainAll(Collection collection) {
        switch (this.a) {
            case 0:
                collection.getClass();
                int size = size();
                boolean zRetainAll = this.c.retainAll(collection);
                if (zRetainAll) {
                    ((C2845xu) this.f).e += this.c.size() - size;
                    c();
                }
                return zRetainAll;
            default:
                collection.getClass();
                size();
                boolean zRetainAll2 = this.c.retainAll(collection);
                if (zRetainAll2) {
                    this.c.size();
                    ((C3199m) this.f).getClass();
                    c();
                }
                return zRetainAll2;
        }
    }

    @Override // java.util.List
    public final Object set(int i, Object obj) {
        switch (this.a) {
            case 0:
                b();
                break;
            default:
                b();
                break;
        }
        return ((List) this.c).set(i, obj);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        switch (this.a) {
            case 0:
                b();
                break;
            default:
                b();
                break;
        }
        return this.c.size();
    }

    @Override // java.util.List
    public final List subList(int i, int i2) {
        switch (this.a) {
            case 0:
                b();
                List listSubList = ((List) this.c).subList(i, i2);
                Rt rt = (Rt) this.e;
                if (rt == null) {
                    rt = this;
                }
                C2845xu c2845xu = (C2845xu) this.g;
                c2845xu.getClass();
                boolean z = listSubList instanceof RandomAccess;
                Object obj = this.b;
                return z ? new Nt(c2845xu, obj, listSubList, rt) : new Rt(c2845xu, obj, listSubList, rt);
            default:
                b();
                List listSubList2 = ((List) this.c).subList(i, i2);
                Rt rt2 = (Rt) this.e;
                if (rt2 == null) {
                    rt2 = this;
                }
                C3199m c3199m = (C3199m) this.g;
                c3199m.getClass();
                boolean z2 = listSubList2 instanceof RandomAccess;
                Object obj2 = this.b;
                return z2 ? new C3163i(c3199m, obj2, listSubList2, rt2) : new Rt(c3199m, obj2, listSubList2, rt2);
        }
    }

    @Override // java.util.AbstractCollection
    public final String toString() {
        switch (this.a) {
            case 0:
                b();
                break;
            default:
                b();
                break;
        }
        return this.c.toString();
    }

    public Rt(C3199m c3199m, Object obj, List list, Rt rt) {
        this.g = c3199m;
        this.f = c3199m;
        this.b = obj;
        this.c = list;
        this.e = rt;
        this.d = rt == null ? null : rt.c;
    }

    @Override // java.util.List
    public final ListIterator listIterator(int i) {
        switch (this.a) {
            case 0:
                b();
                return new Qt(this, i);
            default:
                b();
                return new C3172j(this, i);
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean remove(Object obj) {
        switch (this.a) {
            case 0:
                b();
                boolean zRemove = this.c.remove(obj);
                if (zRemove) {
                    C2845xu c2845xu = (C2845xu) this.f;
                    c2845xu.e--;
                    c();
                }
                return zRemove;
            default:
                b();
                boolean zRemove2 = this.c.remove(obj);
                if (zRemove2) {
                    ((C3199m) this.f).getClass();
                    c();
                }
                return zRemove2;
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean add(Object obj) {
        switch (this.a) {
            case 0:
                b();
                boolean zIsEmpty = this.c.isEmpty();
                boolean zAdd = this.c.add(obj);
                if (zAdd) {
                    ((C2845xu) this.f).e++;
                    if (zIsEmpty) {
                        a();
                        break;
                    }
                }
                break;
            default:
                b();
                boolean zIsEmpty2 = this.c.isEmpty();
                boolean zAdd2 = this.c.add(obj);
                if (zAdd2) {
                    ((C3199m) this.f).getClass();
                    if (zIsEmpty2) {
                        a();
                        break;
                    }
                }
                break;
        }
        return true;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean addAll(Collection collection) {
        switch (this.a) {
            case 0:
                if (!collection.isEmpty()) {
                    int size = size();
                    boolean zAddAll = this.c.addAll(collection);
                    if (zAddAll) {
                        ((C2845xu) this.f).e += this.c.size() - size;
                        if (size == 0) {
                            a();
                            break;
                        }
                    }
                }
                break;
            default:
                if (!collection.isEmpty()) {
                    int size2 = size();
                    boolean zAddAll2 = this.c.addAll(collection);
                    if (zAddAll2) {
                        this.c.size();
                        ((C3199m) this.f).getClass();
                        if (size2 == 0) {
                            a();
                            break;
                        }
                    }
                }
                break;
        }
        return true;
    }
}
