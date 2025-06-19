package com.google.android.gms.internal.ads;

import com.google.android.gms.internal.mlkit_vision_barcode.C3199m;
import com.google.android.gms.internal.mlkit_vision_barcode.C3208n;
import com.google.android.gms.internal.mlkit_vision_barcode.C3308z;
import java.util.AbstractCollection;
import java.util.AbstractMap;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;

/* loaded from: classes2.dex */
public final class Tt extends AbstractCollection {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ Tt(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public final void clear() {
        switch (this.a) {
            case 0:
                ((C2845xu) this.b).b();
                break;
            case 1:
                ((Zt) this.b).clear();
                break;
            case 2:
                ((Jt) this.b).clear();
                break;
            case 3:
                ((com.google.android.gms.internal.mlkit_vision_barcode.r) this.b).clear();
                break;
            case 4:
                ((Jt) this.b).clear();
                break;
            default:
                ((com.google.common.cache.I) this.b).clear();
                break;
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public boolean contains(Object obj) {
        switch (this.a) {
            case 0:
                Iterator it2 = ((Jt) ((C2845xu) this.b).a()).values().iterator();
                while (it2.hasNext()) {
                    if (((Collection) it2.next()).contains(obj)) {
                        return true;
                    }
                }
                return false;
            case 1:
            case 3:
            default:
                return super.contains(obj);
            case 2:
                return ((Jt) this.b).containsValue(obj);
            case 4:
                return ((Jt) this.b).containsValue(obj);
            case 5:
                return ((com.google.common.cache.I) this.b).containsValue(obj);
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public boolean isEmpty() {
        switch (this.a) {
            case 2:
                return ((Jt) this.b).isEmpty();
            case 3:
            default:
                return super.isEmpty();
            case 4:
                return ((Jt) this.b).isEmpty();
            case 5:
                return ((com.google.common.cache.I) this.b).isEmpty();
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable
    public final Iterator iterator() {
        switch (this.a) {
            case 0:
                return new Gt((C2845xu) this.b);
            case 1:
                Zt zt = (Zt) this.b;
                Map mapE = zt.e();
                return mapE != null ? mapE.values().iterator() : new Vt(zt, 2);
            case 2:
                return new C2759vu(((Jt) this.b).entrySet().iterator());
            case 3:
                com.google.android.gms.internal.mlkit_vision_barcode.r rVar = (com.google.android.gms.internal.mlkit_vision_barcode.r) this.b;
                Map mapE2 = rVar.e();
                return mapE2 != null ? mapE2.values().iterator() : new C3208n(rVar, 2);
            case 4:
                return new C3308z(((Jt) this.b).entrySet().iterator());
            default:
                return new com.google.common.cache.n((com.google.common.cache.I) this.b, 2);
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public boolean remove(Object obj) {
        switch (this.a) {
            case 2:
                try {
                    return super.remove(obj);
                } catch (UnsupportedOperationException unused) {
                    Jt jt = (Jt) this.b;
                    for (Map.Entry entry : jt.entrySet()) {
                        if (AbstractC2457os.l(obj, entry.getValue())) {
                            jt.remove(entry.getKey());
                            return true;
                        }
                    }
                    return false;
                }
            case 3:
            default:
                return super.remove(obj);
            case 4:
                try {
                    return super.remove(obj);
                } catch (UnsupportedOperationException unused2) {
                    Jt jt2 = (Jt) this.b;
                    for (Map.Entry entry2 : jt2.entrySet()) {
                        if (com.google.android.gms.internal.mlkit_vision_common.H3.b(obj, entry2.getValue())) {
                            jt2.remove(entry2.getKey());
                            return true;
                        }
                    }
                    return false;
                }
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public boolean removeAll(Collection collection) {
        switch (this.a) {
            case 2:
                try {
                    if (collection != null) {
                        return super.removeAll(collection);
                    }
                    throw null;
                } catch (UnsupportedOperationException unused) {
                    HashSet hashSet = new HashSet();
                    Jt jt = (Jt) this.b;
                    for (Map.Entry entry : jt.entrySet()) {
                        if (collection.contains(entry.getValue())) {
                            hashSet.add(entry.getKey());
                        }
                    }
                    return jt.keySet().removeAll(hashSet);
                }
            case 3:
            default:
                return super.removeAll(collection);
            case 4:
                try {
                    if (collection != null) {
                        return super.removeAll(collection);
                    }
                    throw null;
                } catch (UnsupportedOperationException unused2) {
                    HashSet hashSet2 = new HashSet();
                    Jt jt2 = (Jt) this.b;
                    for (Map.Entry entry2 : jt2.entrySet()) {
                        if (collection.contains(entry2.getValue())) {
                            hashSet2.add(entry2.getKey());
                        }
                    }
                    return ((C3199m) jt2.e).b().removeAll(hashSet2);
                }
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public boolean retainAll(Collection collection) {
        switch (this.a) {
            case 2:
                try {
                    if (collection != null) {
                        return super.retainAll(collection);
                    }
                    throw null;
                } catch (UnsupportedOperationException unused) {
                    HashSet hashSet = new HashSet();
                    Jt jt = (Jt) this.b;
                    for (Map.Entry entry : jt.entrySet()) {
                        if (collection.contains(entry.getValue())) {
                            hashSet.add(entry.getKey());
                        }
                    }
                    return jt.keySet().retainAll(hashSet);
                }
            case 3:
            default:
                return super.retainAll(collection);
            case 4:
                try {
                    if (collection != null) {
                        return super.retainAll(collection);
                    }
                    throw null;
                } catch (UnsupportedOperationException unused2) {
                    HashSet hashSet2 = new HashSet();
                    Jt jt2 = (Jt) this.b;
                    for (Map.Entry entry2 : jt2.entrySet()) {
                        if (collection.contains(entry2.getValue())) {
                            hashSet2.add(entry2.getKey());
                        }
                    }
                    return ((C3199m) jt2.e).b().retainAll(hashSet2);
                }
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public final int size() {
        switch (this.a) {
            case 0:
                return ((C2845xu) this.b).e;
            case 1:
                return ((Zt) this.b).size();
            case 2:
                return ((Jt) this.b).d.size();
            case 3:
                return ((com.google.android.gms.internal.mlkit_vision_barcode.r) this.b).size();
            case 4:
                return ((Jt) this.b).size();
            default:
                return ((com.google.common.cache.I) this.b).size();
        }
    }

    public /* synthetic */ Tt(AbstractMap abstractMap, int i) {
        this.a = i;
        this.b = abstractMap;
    }
}
