package com.quizlet.quizletandroid;

import androidx.camera.camera2.internal.c0;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.N;

/* loaded from: classes3.dex */
public final class n implements dagger.internal.c {
    public final u a;
    public final c0 b;

    public n(u uVar, c0 c0Var) {
        this.a = uVar;
        this.b = c0Var;
    }

    @Override // javax.inject.a
    public final Object get() {
        com.quizlet.features.infra.basestudy.manager.d dVar = (com.quizlet.features.infra.basestudy.manager.d) this.a.D1.get();
        c0 c0Var = this.b;
        return new N(dVar, ((Long) c0Var.b).longValue(), ((Integer) c0Var.c).intValue());
    }
}
