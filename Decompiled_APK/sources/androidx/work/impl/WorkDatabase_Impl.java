package androidx.work.impl;

import android.content.Context;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class WorkDatabase_Impl extends WorkDatabase {
    public volatile androidx.work.impl.model.t m;
    public volatile androidx.work.impl.model.c n;
    public volatile androidx.work.impl.model.v o;
    public volatile androidx.work.impl.model.i p;
    public volatile androidx.work.impl.model.l q;
    public volatile androidx.work.impl.model.n r;
    public volatile androidx.work.impl.model.e s;

    @Override // androidx.work.impl.WorkDatabase
    public final androidx.room.n d() {
        return new androidx.room.n(this, new HashMap(0), new HashMap(0), "Dependency", "WorkSpec", "WorkTag", "SystemIdInfo", "WorkName", "WorkProgress", "Preference");
    }

    @Override // androidx.work.impl.WorkDatabase
    public final androidx.sqlite.db.e e(androidx.room.f fVar) {
        androidx.room.t callback = new androidx.room.t(fVar, new com.airbnb.lottie.network.d(this, 16));
        Context context = fVar.a;
        Intrinsics.checkNotNullParameter(context, "context");
        androidx.sqlite.db.c cVar = new androidx.sqlite.db.c(context);
        cVar.b = fVar.b;
        Intrinsics.checkNotNullParameter(callback, "callback");
        cVar.c = callback;
        return fVar.c.d(cVar.a());
    }

    @Override // androidx.work.impl.WorkDatabase
    public final androidx.work.impl.model.c f() {
        androidx.work.impl.model.c cVar;
        if (this.n != null) {
            return this.n;
        }
        synchronized (this) {
            try {
                if (this.n == null) {
                    this.n = new androidx.work.impl.model.c(this);
                }
                cVar = this.n;
            } catch (Throwable th) {
                throw th;
            }
        }
        return cVar;
    }

    @Override // androidx.work.impl.WorkDatabase
    public final List g(LinkedHashMap linkedHashMap) {
        ArrayList arrayList = new ArrayList();
        arrayList.add(new C1431c(13, 14, 10));
        arrayList.add(new C1431c(11));
        int i = 17;
        arrayList.add(new C1431c(16, i, 12));
        int i2 = 18;
        arrayList.add(new C1431c(i, i2, 13));
        arrayList.add(new C1431c(i2, 19, 14));
        arrayList.add(new C1431c(15));
        arrayList.add(new C1431c(20, 21, 16));
        arrayList.add(new C1431c(22, 23, 17));
        return arrayList;
    }

    @Override // androidx.work.impl.WorkDatabase
    public final Set i() {
        return new HashSet();
    }

    @Override // androidx.work.impl.WorkDatabase
    public final Map j() {
        HashMap map = new HashMap();
        List list = Collections.EMPTY_LIST;
        map.put(androidx.work.impl.model.t.class, list);
        map.put(androidx.work.impl.model.c.class, list);
        map.put(androidx.work.impl.model.v.class, list);
        map.put(androidx.work.impl.model.i.class, list);
        map.put(androidx.work.impl.model.l.class, list);
        map.put(androidx.work.impl.model.n.class, list);
        map.put(androidx.work.impl.model.e.class, list);
        map.put(androidx.work.impl.model.f.class, list);
        return map;
    }

    @Override // androidx.work.impl.WorkDatabase
    public final androidx.work.impl.model.e l() {
        androidx.work.impl.model.e eVar;
        if (this.s != null) {
            return this.s;
        }
        synchronized (this) {
            try {
                if (this.s == null) {
                    this.s = new androidx.work.impl.model.e(this);
                }
                eVar = this.s;
            } catch (Throwable th) {
                throw th;
            }
        }
        return eVar;
    }

    @Override // androidx.work.impl.WorkDatabase
    public final androidx.work.impl.model.i q() {
        androidx.work.impl.model.i iVar;
        if (this.p != null) {
            return this.p;
        }
        synchronized (this) {
            try {
                if (this.p == null) {
                    this.p = new androidx.work.impl.model.i(this);
                }
                iVar = this.p;
            } catch (Throwable th) {
                throw th;
            }
        }
        return iVar;
    }

    @Override // androidx.work.impl.WorkDatabase
    public final androidx.work.impl.model.l s() {
        androidx.work.impl.model.l lVar;
        if (this.q != null) {
            return this.q;
        }
        synchronized (this) {
            try {
                if (this.q == null) {
                    this.q = new androidx.work.impl.model.l(this);
                }
                lVar = this.q;
            } catch (Throwable th) {
                throw th;
            }
        }
        return lVar;
    }

    @Override // androidx.work.impl.WorkDatabase
    public final androidx.work.impl.model.n t() {
        androidx.work.impl.model.n nVar;
        if (this.r != null) {
            return this.r;
        }
        synchronized (this) {
            try {
                if (this.r == null) {
                    this.r = new androidx.work.impl.model.n(this);
                }
                nVar = this.r;
            } catch (Throwable th) {
                throw th;
            }
        }
        return nVar;
    }

    @Override // androidx.work.impl.WorkDatabase
    public final androidx.work.impl.model.t u() {
        androidx.work.impl.model.t tVar;
        if (this.m != null) {
            return this.m;
        }
        synchronized (this) {
            try {
                if (this.m == null) {
                    this.m = new androidx.work.impl.model.t(this);
                }
                tVar = this.m;
            } catch (Throwable th) {
                throw th;
            }
        }
        return tVar;
    }

    @Override // androidx.work.impl.WorkDatabase
    public final androidx.work.impl.model.v v() {
        androidx.work.impl.model.v vVar;
        if (this.o != null) {
            return this.o;
        }
        synchronized (this) {
            try {
                if (this.o == null) {
                    this.o = new androidx.work.impl.model.v(this);
                }
                vVar = this.o;
            } catch (Throwable th) {
                throw th;
            }
        }
        return vVar;
    }
}
