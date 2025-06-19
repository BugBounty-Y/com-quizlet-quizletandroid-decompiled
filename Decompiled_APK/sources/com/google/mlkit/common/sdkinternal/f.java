package com.google.mlkit.common.sdkinternal;

import android.content.Context;
import androidx.appcompat.app.L;
import com.google.android.gms.common.internal.u;
import com.google.mlkit.common.internal.MlKitComponentDiscoveryService;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class f {
    public static final Object b = new Object();
    public static f c;
    public com.google.firebase.components.g a;

    public static f c() {
        f fVar;
        synchronized (b) {
            u.j("MlKitContext has not been initialized", c != null);
            fVar = c;
            u.h(fVar);
        }
        return fVar;
    }

    public static f d(Context context, androidx.camera.core.impl.utils.executor.h hVar) {
        f fVar;
        synchronized (b) {
            u.j("MlKitContext is already initialized", c == null);
            f fVar2 = new f();
            c = fVar2;
            Context applicationContext = context.getApplicationContext();
            if (applicationContext != null) {
                context = applicationContext;
            }
            ArrayList arrayListM = new androidx.work.impl.model.e(12, context, new L(MlKitComponentDiscoveryService.class, 27)).m();
            ArrayList arrayList = new ArrayList();
            ArrayList arrayList2 = new ArrayList();
            com.facebook.appevents.k kVar = com.google.firebase.components.e.Y0;
            arrayList.addAll(arrayListM);
            arrayList2.add(com.google.firebase.components.a.c(context, Context.class, new Class[0]));
            arrayList2.add(com.google.firebase.components.a.c(fVar2, f.class, new Class[0]));
            com.google.firebase.components.g gVar = new com.google.firebase.components.g(hVar, arrayList, arrayList2, kVar);
            fVar2.a = gVar;
            gVar.h(true);
            fVar = c;
        }
        return fVar;
    }

    public final Object a(Class cls) {
        u.j("MlKitContext has been deleted", c == this);
        u.h(this.a);
        return this.a.get(cls);
    }

    public final Context b() {
        return (Context) a(Context.class);
    }
}
