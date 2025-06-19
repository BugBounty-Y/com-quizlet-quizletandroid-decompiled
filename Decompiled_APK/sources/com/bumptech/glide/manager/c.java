package com.bumptech.glide.manager;

import android.content.Context;
import android.net.ConnectivityManager;
import java.util.HashSet;

/* loaded from: classes.dex */
public final class c implements b {
    public final Context a;
    public final com.bumptech.glide.l b;

    public c(Context context, com.bumptech.glide.l lVar) {
        this.a = context.getApplicationContext();
        this.b = lVar;
    }

    @Override // com.bumptech.glide.manager.i
    public final void onDestroy() {
    }

    @Override // com.bumptech.glide.manager.i
    public final void onStart() {
        p pVarF = p.f(this.a);
        com.bumptech.glide.l lVar = this.b;
        synchronized (pVarF) {
            ((HashSet) pVarF.c).add(lVar);
            pVarF.g();
        }
    }

    @Override // com.bumptech.glide.manager.i
    public final void onStop() {
        p pVarF = p.f(this.a);
        com.bumptech.glide.l lVar = this.b;
        synchronized (pVarF) {
            ((HashSet) pVarF.c).remove(lVar);
            if (pVarF.a && ((HashSet) pVarF.c).isEmpty()) {
                androidx.browser.customtabs.k kVar = (androidx.browser.customtabs.k) pVarF.b;
                ((ConnectivityManager) ((com.bumptech.glide.load.engine.k) kVar.c).get()).unregisterNetworkCallback((androidx.work.impl.constraints.d) kVar.d);
                pVarF.a = false;
            }
        }
    }
}
