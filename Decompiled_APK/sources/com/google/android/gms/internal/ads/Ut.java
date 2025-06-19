package com.google.android.gms.internal.ads;

import java.util.Map;
import java.util.NavigableMap;
import java.util.SortedMap;

/* loaded from: classes2.dex */
public abstract class Ut {
    public transient Kt a;
    public transient Tt b;
    public transient Jt c;

    public final Map a() {
        Jt jt = this.c;
        if (jt != null) {
            return jt;
        }
        C2845xu c2845xu = (C2845xu) this;
        Map map = c2845xu.d;
        Jt lt = map instanceof NavigableMap ? new Lt(c2845xu, (NavigableMap) map) : map instanceof SortedMap ? new Ot(c2845xu, (SortedMap) map) : new Jt(c2845xu, map, 0);
        this.c = lt;
        return lt;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof Ut) {
            return a().equals(((Ut) obj).a());
        }
        return false;
    }

    public final int hashCode() {
        return ((Jt) a()).d.hashCode();
    }

    public final String toString() {
        return ((Jt) a()).d.toString();
    }
}
