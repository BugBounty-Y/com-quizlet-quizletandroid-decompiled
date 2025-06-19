package com.bumptech.glide.request;

import android.content.Context;
import android.graphics.drawable.Drawable;
import android.os.SystemClock;
import android.util.Log;
import com.bumptech.glide.load.engine.GlideException;
import com.bumptech.glide.load.engine.j;
import com.bumptech.glide.load.engine.l;
import com.bumptech.glide.load.engine.o;
import com.bumptech.glide.load.engine.v;
import com.bumptech.glide.util.m;
import com.google.android.gms.internal.mlkit_vision_common.B;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;

/* loaded from: classes.dex */
public final class g implements c, com.bumptech.glide.request.target.d {
    public static final boolean A = Log.isLoggable("GlideRequest", 2);
    public final com.bumptech.glide.util.pool.e a;
    public final Object b;
    public final Object c;
    public final Context d;
    public final com.bumptech.glide.e e;
    public final Object f;
    public final Class g;
    public final a h;
    public final int i;
    public final int j;
    public final com.bumptech.glide.g k;
    public final com.bumptech.glide.request.target.e l;
    public final ArrayList m;
    public final com.bumptech.glide.request.transition.a n;
    public final androidx.camera.core.impl.utils.executor.a o;
    public v p;
    public com.quizlet.data.repository.user.a q;
    public volatile l r;
    public Drawable s;
    public Drawable t;
    public Drawable u;
    public int v;
    public int w;
    public boolean x;
    public final RuntimeException y;
    public int z;

    public g(Context context, com.bumptech.glide.e eVar, Object obj, Object obj2, Class cls, a aVar, int i, int i2, com.bumptech.glide.g gVar, com.bumptech.glide.request.target.e eVar2, ArrayList arrayList, d dVar, l lVar, com.bumptech.glide.request.transition.a aVar2) {
        androidx.camera.core.impl.utils.executor.a aVar3 = com.bumptech.glide.util.f.a;
        if (A) {
            String.valueOf(hashCode());
        }
        this.a = new com.bumptech.glide.util.pool.e();
        this.b = obj;
        this.d = context;
        this.e = eVar;
        this.f = obj2;
        this.g = cls;
        this.h = aVar;
        this.i = i;
        this.j = i2;
        this.k = gVar;
        this.l = eVar2;
        this.m = arrayList;
        this.c = dVar;
        this.r = lVar;
        this.n = aVar2;
        this.o = aVar3;
        this.z = 1;
        if (this.y == null && ((Map) eVar.h.b).containsKey(com.bumptech.glide.c.class)) {
            this.y = new RuntimeException("Glide request origin trace");
        }
    }

    @Override // com.bumptech.glide.request.c
    public final boolean a() {
        boolean z;
        synchronized (this.b) {
            z = this.z == 4;
        }
        return z;
    }

    public final void b() {
        if (this.x) {
            throw new IllegalStateException("You can't start or clear loads in RequestListener or Target callbacks. If you're trying to start a fallback request when a load fails, use RequestBuilder#error(RequestBuilder). Otherwise consider posting your into() or clear() calls to the main thread using a Handler instead.");
        }
        this.a.a();
        this.l.c(this);
        com.quizlet.data.repository.user.a aVar = this.q;
        if (aVar != null) {
            synchronized (((l) aVar.d)) {
                ((o) aVar.b).h((g) aVar.c);
            }
            this.q = null;
        }
    }

    @Override // com.bumptech.glide.request.c
    public final boolean c(c cVar) {
        int i;
        int i2;
        Object obj;
        Class cls;
        a aVar;
        com.bumptech.glide.g gVar;
        int size;
        int i3;
        int i4;
        Object obj2;
        Class cls2;
        a aVar2;
        com.bumptech.glide.g gVar2;
        int size2;
        if (!(cVar instanceof g)) {
            return false;
        }
        synchronized (this.b) {
            try {
                i = this.i;
                i2 = this.j;
                obj = this.f;
                cls = this.g;
                aVar = this.h;
                gVar = this.k;
                ArrayList arrayList = this.m;
                size = arrayList != null ? arrayList.size() : 0;
            } finally {
            }
        }
        g gVar3 = (g) cVar;
        synchronized (gVar3.b) {
            try {
                i3 = gVar3.i;
                i4 = gVar3.j;
                obj2 = gVar3.f;
                cls2 = gVar3.g;
                aVar2 = gVar3.h;
                gVar2 = gVar3.k;
                ArrayList arrayList2 = gVar3.m;
                size2 = arrayList2 != null ? arrayList2.size() : 0;
            } finally {
            }
        }
        if (i != i3 || i2 != i4) {
            return false;
        }
        char[] cArr = m.a;
        if ((obj == null ? obj2 == null : obj.equals(obj2)) && cls.equals(cls2)) {
            return (aVar == null ? aVar2 == null : aVar.f(aVar2)) && gVar == gVar2 && size == size2;
        }
        return false;
    }

    /* JADX WARN: Type inference failed for: r3v1, types: [com.bumptech.glide.request.d, java.lang.Object] */
    @Override // com.bumptech.glide.request.c
    public final void clear() {
        synchronized (this.b) {
            try {
                if (this.x) {
                    throw new IllegalStateException("You can't start or clear loads in RequestListener or Target callbacks. If you're trying to start a fallback request when a load fails, use RequestBuilder#error(RequestBuilder). Otherwise consider posting your into() or clear() calls to the main thread using a Handler instead.");
                }
                this.a.a();
                if (this.z == 6) {
                    return;
                }
                b();
                v vVar = this.p;
                if (vVar != null) {
                    this.p = null;
                } else {
                    vVar = null;
                }
                ?? r3 = this.c;
                if (r3 == 0 || r3.j(this)) {
                    this.l.h(e());
                }
                this.z = 6;
                if (vVar != null) {
                    this.r.getClass();
                    l.e(vVar);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.bumptech.glide.request.c
    public final boolean d() {
        boolean z;
        synchronized (this.b) {
            z = this.z == 6;
        }
        return z;
    }

    public final Drawable e() {
        if (this.t == null) {
            a aVar = this.h;
            aVar.getClass();
            this.t = null;
            int i = aVar.d;
            if (i > 0) {
                aVar.getClass();
                Context context = this.d;
                this.t = B.d(context, context, i, context.getTheme());
            }
        }
        return this.t;
    }

    /* JADX WARN: Type inference failed for: r2v3, types: [com.bumptech.glide.request.d, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r4v0, types: [com.bumptech.glide.request.d, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r7v2, types: [com.bumptech.glide.request.d, java.lang.Object] */
    public final void f(GlideException glideException, int i) {
        Drawable drawableE;
        this.a.a();
        synchronized (this.b) {
            try {
                glideException.getClass();
                int i2 = this.e.i;
                if (i2 <= i) {
                    Log.w("Glide", "Load failed for [" + this.f + "] with dimensions [" + this.v + "x" + this.w + "]", glideException);
                    if (i2 <= 4) {
                        glideException.d();
                    }
                }
                this.q = null;
                this.z = 5;
                ?? r7 = this.c;
                if (r7 != 0) {
                    r7.b(this);
                }
                boolean z = true;
                this.x = true;
                try {
                    ArrayList arrayList = this.m;
                    if (arrayList != null) {
                        Iterator it2 = arrayList.iterator();
                        while (it2.hasNext()) {
                            e eVar = (e) it2.next();
                            ?? r4 = this.c;
                            if (r4 != 0) {
                                r4.getRoot().a();
                            }
                            eVar.b();
                        }
                    }
                    ?? r2 = this.c;
                    if (r2 != 0 && !r2.e(this)) {
                        z = false;
                    }
                    if (z) {
                        if (this.f == null) {
                            if (this.u == null) {
                                this.h.getClass();
                                this.u = null;
                            }
                            drawableE = this.u;
                        } else {
                            drawableE = null;
                        }
                        if (drawableE == null) {
                            if (this.s == null) {
                                this.h.getClass();
                                this.s = null;
                            }
                            drawableE = this.s;
                        }
                        if (drawableE == null) {
                            drawableE = e();
                        }
                        this.l.f(drawableE);
                    }
                } finally {
                    this.x = false;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    /* JADX WARN: Type inference failed for: r1v14, types: [com.bumptech.glide.request.d, java.lang.Object] */
    @Override // com.bumptech.glide.request.c
    public final void g() {
        synchronized (this.b) {
            try {
                if (this.x) {
                    throw new IllegalStateException("You can't start or clear loads in RequestListener or Target callbacks. If you're trying to start a fallback request when a load fails, use RequestBuilder#error(RequestBuilder). Otherwise consider posting your into() or clear() calls to the main thread using a Handler instead.");
                }
                this.a.a();
                int i = com.bumptech.glide.util.h.a;
                SystemClock.elapsedRealtimeNanos();
                if (this.f == null) {
                    if (m.i(this.i, this.j)) {
                        this.v = this.i;
                        this.w = this.j;
                    }
                    if (this.u == null) {
                        this.h.getClass();
                        this.u = null;
                    }
                    f(new GlideException("Received null model"), this.u == null ? 5 : 3);
                    return;
                }
                int i2 = this.z;
                if (i2 == 2) {
                    throw new IllegalArgumentException("Cannot restart a running request");
                }
                if (i2 == 4) {
                    h(this.p, 5, false);
                    return;
                }
                ArrayList arrayList = this.m;
                if (arrayList != null) {
                    Iterator it2 = arrayList.iterator();
                    while (it2.hasNext()) {
                    }
                }
                this.z = 3;
                if (m.i(this.i, this.j)) {
                    k(this.i, this.j);
                } else {
                    this.l.e(this);
                }
                int i3 = this.z;
                if (i3 == 2 || i3 == 3) {
                    ?? r1 = this.c;
                    if (r1 == 0 || r1.e(this)) {
                        this.l.g(e());
                    }
                }
                if (A) {
                    SystemClock.elapsedRealtimeNanos();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    /* JADX WARN: Type inference failed for: r9v14, types: [com.bumptech.glide.request.d, java.lang.Object] */
    public final void h(v vVar, int i, boolean z) {
        this.a.a();
        v vVar2 = null;
        try {
            synchronized (this.b) {
                try {
                    this.q = null;
                    if (vVar == null) {
                        f(new GlideException("Expected to receive a Resource<R> with an object of " + this.g + " inside, but instead got null."), 5);
                        return;
                    }
                    Object obj = vVar.get();
                    try {
                        if (obj == null || !this.g.isAssignableFrom(obj.getClass())) {
                            this.p = null;
                            StringBuilder sb = new StringBuilder("Expected to receive an object of ");
                            sb.append(this.g);
                            sb.append(" but instead got ");
                            sb.append(obj != null ? obj.getClass() : "");
                            sb.append("{");
                            sb.append(obj);
                            sb.append("} inside Resource{");
                            sb.append(vVar);
                            sb.append("}.");
                            sb.append(obj != null ? "" : " To indicate failure return a null Resource object, rather than a Resource object containing null data.");
                            f(new GlideException(sb.toString()), 5);
                        } else {
                            ?? r9 = this.c;
                            if (r9 == 0 || r9.f(this)) {
                                j(vVar, obj, i);
                                return;
                            } else {
                                this.p = null;
                                this.z = 4;
                            }
                        }
                        this.r.getClass();
                        l.e(vVar);
                    } catch (Throwable th) {
                        vVar2 = vVar;
                        th = th;
                        throw th;
                    }
                } catch (Throwable th2) {
                    th = th2;
                }
            }
        } catch (Throwable th3) {
            if (vVar2 != null) {
                this.r.getClass();
                l.e(vVar2);
            }
            throw th3;
        }
    }

    @Override // com.bumptech.glide.request.c
    public final boolean i() {
        boolean z;
        synchronized (this.b) {
            z = this.z == 4;
        }
        return z;
    }

    @Override // com.bumptech.glide.request.c
    public final boolean isRunning() {
        boolean z;
        synchronized (this.b) {
            int i = this.z;
            z = i == 2 || i == 3;
        }
        return z;
    }

    /* JADX WARN: Type inference failed for: r4v1, types: [com.bumptech.glide.request.d, java.lang.Object] */
    public final void j(v vVar, Object obj, int i) {
        ?? r4 = this.c;
        if (r4 != 0) {
            r4.getRoot().a();
        }
        this.z = 4;
        this.p = vVar;
        if (this.e.i <= 3) {
            Objects.toString(this.f);
            int i2 = com.bumptech.glide.util.h.a;
            SystemClock.elapsedRealtimeNanos();
        }
        if (r4 != 0) {
            r4.h(this);
        }
        this.x = true;
        try {
            ArrayList arrayList = this.m;
            if (arrayList != null) {
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    ((e) it2.next()).a(obj);
                }
            }
            this.n.getClass();
            this.l.a(obj);
            this.x = false;
        } catch (Throwable th) {
            this.x = false;
            throw th;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void k(int i, int i2) throws Throwable {
        g gVar = this;
        int iRound = i;
        gVar.a.a();
        Object obj = gVar.b;
        synchronized (obj) {
            try {
                try {
                    boolean z = A;
                    if (z) {
                        int i3 = com.bumptech.glide.util.h.a;
                        SystemClock.elapsedRealtimeNanos();
                    }
                    if (gVar.z == 3) {
                        gVar.z = 2;
                        gVar.h.getClass();
                        if (iRound != Integer.MIN_VALUE) {
                            iRound = Math.round(iRound * 1.0f);
                        }
                        gVar.v = iRound;
                        gVar.w = i2 == Integer.MIN_VALUE ? i2 : Math.round(1.0f * i2);
                        if (z) {
                            int i4 = com.bumptech.glide.util.h.a;
                            SystemClock.elapsedRealtimeNanos();
                        }
                        l lVar = gVar.r;
                        try {
                            com.bumptech.glide.e eVar = gVar.e;
                            Object obj2 = gVar.f;
                            a aVar = gVar.h;
                            try {
                                com.bumptech.glide.load.e eVar2 = aVar.h;
                                int i5 = gVar.v;
                                try {
                                    int i6 = gVar.w;
                                    Class cls = aVar.l;
                                    try {
                                        Class cls2 = gVar.g;
                                        com.bumptech.glide.g gVar2 = gVar.k;
                                        try {
                                            j jVar = aVar.b;
                                            com.bumptech.glide.util.c cVar = aVar.k;
                                            try {
                                                boolean z2 = aVar.i;
                                                boolean z3 = aVar.o;
                                                try {
                                                    com.bumptech.glide.load.h hVar = aVar.j;
                                                    boolean z4 = aVar.e;
                                                    boolean z5 = aVar.p;
                                                    androidx.camera.core.impl.utils.executor.a aVar2 = gVar.o;
                                                    gVar = obj;
                                                    try {
                                                        gVar.q = lVar.a(eVar, obj2, eVar2, i5, i6, cls, cls2, gVar2, jVar, cVar, z2, z3, hVar, z4, z5, gVar, aVar2);
                                                        if (gVar.z != 2) {
                                                            gVar.q = null;
                                                        }
                                                        if (z) {
                                                            int i7 = com.bumptech.glide.util.h.a;
                                                            SystemClock.elapsedRealtimeNanos();
                                                        }
                                                    } catch (Throwable th) {
                                                        th = th;
                                                        throw th;
                                                    }
                                                } catch (Throwable th2) {
                                                    th = th2;
                                                    gVar = obj;
                                                }
                                            } catch (Throwable th3) {
                                                th = th3;
                                                gVar = obj;
                                            }
                                        } catch (Throwable th4) {
                                            th = th4;
                                            gVar = obj;
                                        }
                                    } catch (Throwable th5) {
                                        th = th5;
                                        gVar = obj;
                                    }
                                } catch (Throwable th6) {
                                    th = th6;
                                    gVar = obj;
                                }
                            } catch (Throwable th7) {
                                th = th7;
                                gVar = obj;
                            }
                        } catch (Throwable th8) {
                            th = th8;
                            gVar = obj;
                        }
                    }
                } catch (Throwable th9) {
                    th = th9;
                }
            } catch (Throwable th10) {
                th = th10;
                gVar = obj;
            }
        }
    }

    @Override // com.bumptech.glide.request.c
    public final void pause() {
        synchronized (this.b) {
            try {
                if (isRunning()) {
                    clear();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final String toString() {
        Object obj;
        Class cls;
        synchronized (this.b) {
            obj = this.f;
            cls = this.g;
        }
        return super.toString() + "[model=" + obj + ", transcodeClass=" + cls + "]";
    }
}
