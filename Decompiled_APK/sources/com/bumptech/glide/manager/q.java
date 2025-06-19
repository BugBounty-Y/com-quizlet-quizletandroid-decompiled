package com.bumptech.glide.manager;

import java.util.Collections;
import java.util.Iterator;
import java.util.Set;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public final class q implements i {
    public final Set a = Collections.newSetFromMap(new WeakHashMap());

    @Override // com.bumptech.glide.manager.i
    public final void onDestroy() {
        Iterator it2 = com.bumptech.glide.util.m.e(this.a).iterator();
        while (it2.hasNext()) {
            ((com.bumptech.glide.request.target.e) it2.next()).onDestroy();
        }
    }

    @Override // com.bumptech.glide.manager.i
    public final void onStart() {
        Iterator it2 = com.bumptech.glide.util.m.e(this.a).iterator();
        while (it2.hasNext()) {
            ((com.bumptech.glide.request.target.e) it2.next()).onStart();
        }
    }

    @Override // com.bumptech.glide.manager.i
    public final void onStop() {
        Iterator it2 = com.bumptech.glide.util.m.e(this.a).iterator();
        while (it2.hasNext()) {
            ((com.bumptech.glide.request.target.e) it2.next()).onStop();
        }
    }
}
