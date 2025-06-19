package com.google.android.gms.internal.ads;

import com.google.android.gms.internal.mlkit_vision_barcode.C3136f;
import com.google.android.gms.internal.mlkit_vision_barcode.C3145g;
import com.google.android.gms.internal.mlkit_vision_barcode.C3163i;
import com.google.android.gms.internal.mlkit_vision_barcode.C3199m;
import java.io.Serializable;
import java.util.AbstractCollection;
import java.util.AbstractMap;
import java.util.AbstractSet;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.RandomAccess;
import java.util.Set;
import java.util.SortedMap;

/* loaded from: classes2.dex */
public class Jt extends AbstractMap {
    public final /* synthetic */ int a;
    public transient AbstractSet b;
    public transient AbstractCollection c;
    public final transient Map d;
    public final /* synthetic */ Serializable e;

    public /* synthetic */ Jt(Serializable serializable, Map map, int i) {
        this.a = i;
        this.e = serializable;
        this.d = map;
    }

    public C2115gu a(Map.Entry entry) {
        Object key = entry.getKey();
        Collection collection = (Collection) entry.getValue();
        C2845xu c2845xu = (C2845xu) this.e;
        List list = (List) collection;
        return new C2115gu(key, list instanceof RandomAccess ? new Nt(c2845xu, key, list, null) : new Rt(c2845xu, key, list, (Rt) null));
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final void clear() {
        switch (this.a) {
            case 0:
                C2845xu c2845xu = (C2845xu) this.e;
                if (this.d != c2845xu.d) {
                    It it2 = new It(this);
                    while (it2.hasNext()) {
                        it2.next();
                        it2.remove();
                    }
                    break;
                } else {
                    c2845xu.b();
                    break;
                }
            default:
                C3199m c3199m = (C3199m) this.e;
                if (((com.google.android.gms.internal.mlkit_vision_barcode.r) this.d) != c3199m.c) {
                    C3145g c3145g = new C3145g(this);
                    while (c3145g.hasNext()) {
                        c3145g.next();
                        c3145g.remove();
                    }
                    break;
                } else {
                    com.google.android.gms.internal.mlkit_vision_barcode.r rVar = c3199m.c;
                    Iterator it3 = rVar.values().iterator();
                    while (it3.hasNext()) {
                        ((Collection) it3.next()).clear();
                    }
                    rVar.clear();
                    break;
                }
        }
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final boolean containsKey(Object obj) {
        switch (this.a) {
            case 0:
                Map map = this.d;
                map.getClass();
                try {
                    return map.containsKey(obj);
                } catch (ClassCastException | NullPointerException unused) {
                    return false;
                }
            default:
                com.google.android.gms.internal.mlkit_vision_barcode.r rVar = (com.google.android.gms.internal.mlkit_vision_barcode.r) this.d;
                rVar.getClass();
                try {
                    return rVar.containsKey(obj);
                } catch (ClassCastException | NullPointerException unused2) {
                    return false;
                }
        }
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Set entrySet() {
        switch (this.a) {
            case 0:
                Ht ht = (Ht) this.b;
                if (ht != null) {
                    return ht;
                }
                Ht ht2 = new Ht(this);
                this.b = ht2;
                return ht2;
            default:
                C3136f c3136f = (C3136f) this.b;
                if (c3136f != null) {
                    return c3136f;
                }
                C3136f c3136f2 = new C3136f(this);
                this.b = c3136f2;
                return c3136f2;
        }
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final boolean equals(Object obj) {
        switch (this.a) {
            case 0:
                if (this == obj || this.d.equals(obj)) {
                }
                break;
            default:
                if (this == obj || ((com.google.android.gms.internal.mlkit_vision_barcode.r) this.d).equals(obj)) {
                }
                break;
        }
        return true;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Object get(Object obj) {
        Object obj2;
        Object obj3;
        switch (this.a) {
            case 0:
                Map map = this.d;
                map.getClass();
                try {
                    obj2 = map.get(obj);
                } catch (ClassCastException | NullPointerException unused) {
                    obj2 = null;
                }
                Collection collection = (Collection) obj2;
                if (collection == null) {
                    return null;
                }
                C2845xu c2845xu = (C2845xu) this.e;
                List list = (List) collection;
                return list instanceof RandomAccess ? new Nt(c2845xu, obj, list, null) : new Rt(c2845xu, obj, list, (Rt) null);
            default:
                com.google.android.gms.internal.mlkit_vision_barcode.r rVar = (com.google.android.gms.internal.mlkit_vision_barcode.r) this.d;
                rVar.getClass();
                try {
                    obj3 = rVar.get(obj);
                } catch (ClassCastException | NullPointerException unused2) {
                    obj3 = null;
                }
                Collection collection2 = (Collection) obj3;
                if (collection2 == null) {
                    return null;
                }
                C3199m c3199m = (C3199m) this.e;
                List list2 = (List) collection2;
                return list2 instanceof RandomAccess ? new C3163i(c3199m, obj, list2, null) : new Rt(c3199m, obj, list2, (Rt) null);
        }
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final int hashCode() {
        switch (this.a) {
            case 0:
                return this.d.hashCode();
            default:
                return ((com.google.android.gms.internal.mlkit_vision_barcode.r) this.d).hashCode();
        }
    }

    @Override // java.util.AbstractMap, java.util.Map
    public Set keySet() {
        switch (this.a) {
            case 0:
                C2845xu c2845xu = (C2845xu) this.e;
                Kt mt = c2845xu.a;
                if (mt == null) {
                    Map map = c2845xu.d;
                    mt = map instanceof NavigableMap ? new Mt(c2845xu, (NavigableMap) map) : map instanceof SortedMap ? new Pt(c2845xu, (SortedMap) map) : new Kt(c2845xu, map);
                    c2845xu.a = mt;
                }
                return mt;
            default:
                C3199m c3199m = (C3199m) this.e;
                C3136f c3136f = c3199m.a;
                if (c3136f != null) {
                    return c3136f;
                }
                C3136f c3136f2 = new C3136f(c3199m, c3199m.c);
                c3199m.a = c3136f2;
                return c3136f2;
        }
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final /* bridge */ /* synthetic */ Object remove(Object obj) {
        switch (this.a) {
            case 0:
                Collection collection = (Collection) this.d.remove(obj);
                if (collection == null) {
                    return null;
                }
                C2845xu c2845xu = (C2845xu) this.e;
                List list = (List) c2845xu.f.zza();
                list.addAll(collection);
                c2845xu.e -= collection.size();
                collection.clear();
                return list;
            default:
                Collection collection2 = (Collection) ((com.google.android.gms.internal.mlkit_vision_barcode.r) this.d).remove(obj);
                if (collection2 == null) {
                    return null;
                }
                ArrayList arrayList = new ArrayList(3);
                arrayList.addAll(collection2);
                collection2.size();
                collection2.clear();
                return arrayList;
        }
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final int size() {
        switch (this.a) {
            case 0:
                return this.d.size();
            default:
                return ((com.google.android.gms.internal.mlkit_vision_barcode.r) this.d).size();
        }
    }

    @Override // java.util.AbstractMap
    public final String toString() {
        switch (this.a) {
            case 0:
                return this.d.toString();
            default:
                return ((com.google.android.gms.internal.mlkit_vision_barcode.r) this.d).toString();
        }
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Collection values() {
        switch (this.a) {
            case 0:
                Tt tt = (Tt) this.c;
                if (tt != null) {
                    return tt;
                }
                Tt tt2 = new Tt((AbstractMap) this, 2);
                this.c = tt2;
                return tt2;
            default:
                Tt tt3 = (Tt) this.c;
                if (tt3 != null) {
                    return tt3;
                }
                Tt tt4 = new Tt((AbstractMap) this, 4);
                this.c = tt4;
                return tt4;
        }
    }
}
