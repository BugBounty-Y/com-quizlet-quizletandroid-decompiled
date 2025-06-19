package coil3.util;

import android.content.ComponentCallbacks2;
import android.content.Context;
import android.content.res.Configuration;
import coil3.p;
import coil3.u;
import com.android.billingclient.api.s;
import java.lang.ref.WeakReference;
import java.util.LinkedHashMap;
import kotlin.Unit;

/* loaded from: classes.dex */
public final class a implements ComponentCallbacks2 {
    public final WeakReference a;
    public Context b;
    public boolean c;

    public a(u uVar) {
        this.a = new WeakReference(uVar);
    }

    public final synchronized void a() {
        try {
            if (this.c) {
                return;
            }
            this.c = true;
            Context context = this.b;
            if (context != null) {
                context.unregisterComponentCallbacks(this);
            }
            this.a.clear();
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // android.content.ComponentCallbacks
    public final synchronized void onConfigurationChanged(Configuration configuration) {
        if (((u) this.a.get()) == null) {
            a();
        }
    }

    @Override // android.content.ComponentCallbacks
    public final synchronized void onLowMemory() {
        onTrimMemory(80);
    }

    @Override // android.content.ComponentCallbacks2
    public final synchronized void onTrimMemory(int i) {
        coil3.memory.c cVar;
        long jA;
        try {
            u uVar = (u) this.a.get();
            if (uVar != null) {
                p pVar = uVar.a;
                if (i >= 40) {
                    coil3.memory.c cVar2 = (coil3.memory.c) pVar.c.getValue();
                    if (cVar2 != null) {
                        synchronized (cVar2.c) {
                            cVar2.a.clear();
                            s sVar = cVar2.b;
                            sVar.b = 0;
                            ((LinkedHashMap) sVar.c).clear();
                            Unit unit = Unit.a;
                        }
                    }
                } else if (i >= 10 && (cVar = (coil3.memory.c) pVar.c.getValue()) != null) {
                    synchronized (cVar.c) {
                        jA = cVar.a.a();
                    }
                    long j = jA / 2;
                    synchronized (cVar.c) {
                        cVar.a.p(j);
                        Unit unit2 = Unit.a;
                    }
                }
            } else {
                a();
            }
        } finally {
        }
    }
}
