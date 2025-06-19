package com.google.android.gms.internal.mlkit_vision_barcode;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.ads.Jt;
import com.google.android.gms.internal.ads.Mu;
import java.util.AbstractMap;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.f, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3136f extends Mu {
    public final /* synthetic */ int b = 0;
    public final AbstractMap c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C3136f(Jt jt) {
        super(1);
        this.c = jt;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final void clear() {
        switch (this.b) {
            case 0:
                ((Jt) this.c).clear();
                break;
            default:
                Iterator it2 = iterator();
                while (true) {
                    C3154h c3154h = (C3154h) it2;
                    if (!c3154h.hasNext()) {
                        break;
                    } else {
                        c3154h.next();
                        c3154h.remove();
                    }
                }
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        switch (this.b) {
            case 0:
                try {
                    return ((r) ((Jt) this.c).d).entrySet().contains(obj);
                } catch (ClassCastException | NullPointerException unused) {
                    return false;
                }
            default:
                return ((r) this.c).containsKey(obj);
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public boolean containsAll(Collection collection) {
        switch (this.b) {
            case 1:
                return ((r) this.c).keySet().containsAll(collection);
            default:
                return super.containsAll(collection);
        }
    }

    @Override // java.util.AbstractSet, java.util.Collection, java.util.Set
    public boolean equals(Object obj) {
        switch (this.b) {
            case 1:
                return this == obj || ((r) this.c).keySet().equals(obj);
            default:
                return super.equals(obj);
        }
    }

    @Override // java.util.AbstractSet, java.util.Collection, java.util.Set
    public int hashCode() {
        switch (this.b) {
            case 1:
                return ((r) this.c).keySet().hashCode();
            default:
                return super.hashCode();
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean isEmpty() {
        switch (this.b) {
            case 0:
                return ((Jt) this.c).isEmpty();
            default:
                return ((r) this.c).isEmpty();
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.Set
    public final Iterator iterator() {
        switch (this.b) {
            case 0:
                return new C3145g((Jt) this.c);
            default:
                return new C3154h(this, ((r) this.c).entrySet().iterator());
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean remove(Object obj) {
        Object objRemove;
        switch (this.b) {
            case 0:
                if (!contains(obj)) {
                    return false;
                }
                Map.Entry entry = (Map.Entry) obj;
                Objects.requireNonNull(entry);
                try {
                    objRemove = ((C3199m) ((Jt) this.c).e).c.remove(entry.getKey());
                } catch (ClassCastException | NullPointerException unused) {
                    objRemove = null;
                }
                Collection collection = (Collection) objRemove;
                if (collection != null) {
                    collection.size();
                    collection.clear();
                }
                return true;
            default:
                Collection collection2 = (Collection) ((r) this.c).remove(obj);
                if (collection2 != null) {
                    int size = collection2.size();
                    collection2.clear();
                    if (size > 0) {
                        return true;
                    }
                }
                return false;
        }
    }

    @Override // com.google.android.gms.internal.ads.Mu, java.util.AbstractSet, java.util.AbstractCollection, java.util.Collection, java.util.Set
    public boolean removeAll(Collection collection) {
        switch (this.b) {
            case 0:
                try {
                    if (collection != null) {
                        return com.google.android.gms.internal.mlkit_vision_common.M3.b(this, collection);
                    }
                    throw null;
                } catch (UnsupportedOperationException unused) {
                    Iterator it2 = collection.iterator();
                    boolean zRemove = false;
                    while (it2.hasNext()) {
                        zRemove |= remove(it2.next());
                    }
                    return zRemove;
                }
            default:
                return super.removeAll(collection);
        }
    }

    @Override // com.google.android.gms.internal.ads.Mu, java.util.AbstractCollection, java.util.Collection, java.util.Set
    public boolean retainAll(Collection collection) {
        int iCeil;
        switch (this.b) {
            case 0:
                try {
                    if (collection != null) {
                        return super.retainAll(collection);
                    }
                    throw null;
                } catch (UnsupportedOperationException unused) {
                    int size = collection.size();
                    if (size >= 3) {
                        iCeil = size < 1073741824 ? (int) Math.ceil(size / 0.75d) : SubsamplingScaleImageView.TILE_SIZE_AUTO;
                    } else {
                        if (size < 0) {
                            throw new IllegalArgumentException(android.support.v4.media.session.a.f(size, "expectedSize cannot be negative but was: "));
                        }
                        iCeil = size + 1;
                    }
                    HashSet hashSet = new HashSet(iCeil);
                    for (Object obj : collection) {
                        if (contains(obj) && (obj instanceof Map.Entry)) {
                            hashSet.add(((Map.Entry) obj).getKey());
                        }
                    }
                    C3199m c3199m = (C3199m) ((Jt) this.c).e;
                    C3136f c3136f = c3199m.a;
                    if (c3136f == null) {
                        c3136f = new C3136f(c3199m, c3199m.c);
                        c3199m.a = c3136f;
                    }
                    return c3136f.retainAll(hashSet);
                }
            default:
                return super.retainAll(collection);
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final int size() {
        switch (this.b) {
            case 0:
                return ((r) ((Jt) this.c).d).size();
            default:
                return ((r) this.c).size();
        }
    }

    public C3136f(C3199m c3199m, r rVar) {
        super(1);
        this.c = rVar;
    }
}
