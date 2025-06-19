package com.google.firebase;

import android.app.Application;
import android.content.Context;
import android.content.IntentFilter;
import android.os.Trace;
import android.util.Log;
import androidx.appcompat.app.L;
import androidx.collection.C0208f;
import com.google.android.gms.common.api.internal.ComponentCallbacks2C1645c;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3233p6;
import com.google.firebase.components.ComponentDiscoveryService;
import com.google.firebase.components.l;
import com.google.firebase.concurrent.ExecutorsRegistrar;
import com.google.firebase.concurrent.j;
import com.google.firebase.provider.FirebaseInitProvider;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class h {
    public static final Object k = new Object();
    public static final C0208f l = new C0208f(0);
    public final Context a;
    public final String b;
    public final i c;
    public final com.google.firebase.components.g d;
    public final AtomicBoolean e;
    public final AtomicBoolean f;
    public final l g;
    public final com.google.firebase.inject.b h;
    public final CopyOnWriteArrayList i;
    public final CopyOnWriteArrayList j;

    public h(Context context, String str, i iVar) {
        AtomicBoolean atomicBoolean = new AtomicBoolean(false);
        this.e = atomicBoolean;
        this.f = new AtomicBoolean();
        CopyOnWriteArrayList copyOnWriteArrayList = new CopyOnWriteArrayList();
        this.i = copyOnWriteArrayList;
        this.j = new CopyOnWriteArrayList();
        this.a = context;
        u.e(str);
        this.b = str;
        this.c = iVar;
        a aVar = FirebaseInitProvider.a;
        Trace.beginSection("Firebase");
        Trace.beginSection("ComponentDiscovery");
        ArrayList arrayListM = new androidx.work.impl.model.e(12, context, new L(ComponentDiscoveryService.class, 27)).m();
        Trace.endSection();
        Trace.beginSection("Runtime");
        j jVar = j.a;
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = new ArrayList();
        arrayList.addAll(arrayListM);
        arrayList.add(new com.google.firebase.components.c(new FirebaseCommonRegistrar(), 1));
        arrayList.add(new com.google.firebase.components.c(new ExecutorsRegistrar(), 1));
        arrayList2.add(com.google.firebase.components.a.c(context, Context.class, new Class[0]));
        arrayList2.add(com.google.firebase.components.a.c(this, h.class, new Class[0]));
        arrayList2.add(com.google.firebase.components.a.c(iVar, i.class, new Class[0]));
        com.google.android.gms.internal.mlkit_common.u uVar = new com.google.android.gms.internal.mlkit_common.u(19);
        if (AbstractC3233p6.b(context) && FirebaseInitProvider.b.get()) {
            arrayList2.add(com.google.firebase.components.a.c(aVar, a.class, new Class[0]));
        }
        com.google.firebase.components.g gVar = new com.google.firebase.components.g(jVar, arrayList, arrayList2, uVar);
        this.d = gVar;
        Trace.endSection();
        this.g = new l(new d(0, this, context));
        this.h = gVar.b(com.google.firebase.heartbeatinfo.d.class);
        e eVar = new e(this);
        a();
        if (atomicBoolean.get()) {
            ComponentCallbacks2C1645c.e.a.get();
        }
        copyOnWriteArrayList.add(eVar);
        Trace.endSection();
    }

    public static h c() {
        h hVar;
        synchronized (k) {
            try {
                hVar = (h) l.get("[DEFAULT]");
                if (hVar == null) {
                    throw new IllegalStateException("Default FirebaseApp is not initialized in this process " + com.google.android.gms.common.util.c.h() + ". Make sure to call FirebaseApp.initializeApp(Context) first.");
                }
                ((com.google.firebase.heartbeatinfo.d) hVar.h.get()).b();
            } catch (Throwable th) {
                throw th;
            }
        }
        return hVar;
    }

    public static h f(Context context) {
        synchronized (k) {
            try {
                if (l.containsKey("[DEFAULT]")) {
                    return c();
                }
                i iVarA = i.a(context);
                if (iVarA == null) {
                    Log.w("FirebaseApp", "Default FirebaseApp failed to initialize because no default options were found. This usually means that com.google.gms:google-services was not applied to your gradle project.");
                    return null;
                }
                return g(context, iVarA);
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public static h g(Context context, i iVar) {
        h hVar;
        AtomicReference atomicReference = f.a;
        if (context.getApplicationContext() instanceof Application) {
            Application application = (Application) context.getApplicationContext();
            AtomicReference atomicReference2 = f.a;
            if (atomicReference2.get() == null) {
                f fVar = new f();
                while (true) {
                    if (atomicReference2.compareAndSet(null, fVar)) {
                        ComponentCallbacks2C1645c.b(application);
                        ComponentCallbacks2C1645c.e.a(fVar);
                        break;
                    }
                    if (atomicReference2.get() != null) {
                        break;
                    }
                }
            }
        }
        if (context.getApplicationContext() != null) {
            context = context.getApplicationContext();
        }
        synchronized (k) {
            C0208f c0208f = l;
            u.j("FirebaseApp name [DEFAULT] already exists!", !c0208f.containsKey("[DEFAULT]"));
            u.i(context, "Application context cannot be null.");
            hVar = new h(context, "[DEFAULT]", iVar);
            c0208f.put("[DEFAULT]", hVar);
        }
        hVar.e();
        return hVar;
    }

    public final void a() {
        u.j("FirebaseApp was deleted", !this.f.get());
    }

    public final Object b(Class cls) {
        a();
        return this.d.get(cls);
    }

    public final String d() {
        StringBuilder sb = new StringBuilder();
        a();
        sb.append(com.google.android.gms.common.util.c.g(this.b.getBytes(Charset.defaultCharset())));
        sb.append("+");
        a();
        sb.append(com.google.android.gms.common.util.c.g(this.c.b.getBytes(Charset.defaultCharset())));
        return sb.toString();
    }

    public final void e() {
        Context context = this.a;
        boolean zB = AbstractC3233p6.b(context);
        String str = this.b;
        if (zB) {
            StringBuilder sb = new StringBuilder("Device unlocked: initializing all Firebase APIs for app ");
            a();
            sb.append(str);
            Log.i("FirebaseApp", sb.toString());
            a();
            this.d.h("[DEFAULT]".equals(str));
            ((com.google.firebase.heartbeatinfo.d) this.h.get()).b();
            return;
        }
        StringBuilder sb2 = new StringBuilder("Device in Direct Boot Mode: postponing initialization of Firebase APIs for app ");
        a();
        sb2.append(str);
        Log.i("FirebaseApp", sb2.toString());
        AtomicReference atomicReference = g.b;
        if (atomicReference.get() == null) {
            g gVar = new g(context);
            while (!atomicReference.compareAndSet(null, gVar)) {
                if (atomicReference.get() != null) {
                    return;
                }
            }
            context.registerReceiver(gVar, new IntentFilter("android.intent.action.USER_UNLOCKED"));
        }
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        hVar.a();
        return this.b.equals(hVar.b);
    }

    public final boolean h() {
        boolean z;
        a();
        com.google.firebase.internal.a aVar = (com.google.firebase.internal.a) this.g.get();
        synchronized (aVar) {
            z = aVar.a;
        }
        return z;
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    public final String toString() {
        androidx.compose.foundation.text.input.internal.u uVar = new androidx.compose.foundation.text.input.internal.u(this);
        uVar.b(this.b, "name");
        uVar.b(this.c, "options");
        return uVar.toString();
    }
}
