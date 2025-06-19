package com.bumptech.glide.manager;

import androidx.lifecycle.C;
import java.util.HashMap;

/* loaded from: classes.dex */
public final class j implements i {
    public final /* synthetic */ C a;
    public final /* synthetic */ androidx.work.impl.model.e b;

    public j(androidx.work.impl.model.e eVar, C c) {
        this.b = eVar;
        this.a = c;
    }

    @Override // com.bumptech.glide.manager.i
    public final void onDestroy() {
        ((HashMap) this.b.b).remove(this.a);
    }

    @Override // com.bumptech.glide.manager.i
    public final void onStart() {
    }

    @Override // com.bumptech.glide.manager.i
    public final void onStop() {
    }
}
