package com.bumptech.glide;

import com.google.android.gms.internal.measurement.C3083y1;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/* loaded from: classes.dex */
public final class l implements com.bumptech.glide.manager.a {
    public final C3083y1 a;
    public final /* synthetic */ m b;

    public l(m mVar, C3083y1 c3083y1) {
        this.b = mVar;
        this.a = c3083y1;
    }

    @Override // com.bumptech.glide.manager.a
    public final void a(boolean z) {
        if (z) {
            synchronized (this.b) {
                C3083y1 c3083y1 = this.a;
                Iterator it2 = com.bumptech.glide.util.m.e((Set) c3083y1.c).iterator();
                while (it2.hasNext()) {
                    com.bumptech.glide.request.c cVar = (com.bumptech.glide.request.c) it2.next();
                    if (!cVar.i() && !cVar.d()) {
                        cVar.clear();
                        if (c3083y1.b) {
                            ((HashSet) c3083y1.d).add(cVar);
                        } else {
                            cVar.g();
                        }
                    }
                }
            }
        }
    }
}
