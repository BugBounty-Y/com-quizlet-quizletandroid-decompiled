package com.airbnb.lottie;

import android.os.Handler;
import android.os.Looper;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.concurrent.Callable;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/* loaded from: classes.dex */
public final class A {
    public static final Executor e;
    public final LinkedHashSet a = new LinkedHashSet(1);
    public final LinkedHashSet b = new LinkedHashSet(1);
    public final Handler c = new Handler(Looper.getMainLooper());
    public volatile z d = null;

    static {
        if ("true".equals(System.getProperty("lottie.testing.directExecutor"))) {
            e = new androidx.arch.core.executor.a(1);
        } else {
            e = Executors.newCachedThreadPool(new com.airbnb.lottie.utils.d());
        }
    }

    public A(h hVar) {
        d(new z(hVar));
    }

    public final synchronized void a(x xVar) {
        Throwable th;
        try {
            z zVar = this.d;
            if (zVar != null && (th = zVar.b) != null) {
                xVar.onResult(th);
            }
            this.b.add(xVar);
        } catch (Throwable th2) {
            throw th2;
        }
    }

    public final synchronized void b(x xVar) {
        h hVar;
        try {
            z zVar = this.d;
            if (zVar != null && (hVar = zVar.a) != null) {
                xVar.onResult(hVar);
            }
            this.a.add(xVar);
        } catch (Throwable th) {
            throw th;
        }
    }

    public final void c() {
        z zVar = this.d;
        if (zVar == null) {
            return;
        }
        h hVar = zVar.a;
        if (hVar != null) {
            synchronized (this) {
                Iterator it2 = new ArrayList(this.a).iterator();
                while (it2.hasNext()) {
                    ((x) it2.next()).onResult(hVar);
                }
            }
            return;
        }
        Throwable th = zVar.b;
        synchronized (this) {
            ArrayList arrayList = new ArrayList(this.b);
            if (arrayList.isEmpty()) {
                com.airbnb.lottie.utils.c.c("Lottie encountered an error but no failure listener was added:", th);
                return;
            }
            Iterator it3 = arrayList.iterator();
            while (it3.hasNext()) {
                ((x) it3.next()).onResult(th);
            }
        }
    }

    public final void d(z zVar) {
        if (this.d != null) {
            throw new IllegalStateException("A task may only be set once.");
        }
        this.d = zVar;
        if (Looper.myLooper() == Looper.getMainLooper()) {
            c();
        } else {
            this.c.post(new androidx.compose.ui.text.input.C(this, 12));
        }
    }

    public A(Callable callable, boolean z) {
        if (z) {
            try {
                d((z) callable.call());
                return;
            } catch (Throwable th) {
                d(new z(th));
                return;
            }
        }
        Executor executor = e;
        androidx.loader.content.d dVar = new androidx.loader.content.d(callable);
        dVar.b = this;
        executor.execute(dVar);
    }
}
