package com.google.android.material.bottomappbar;

import com.google.android.gms.internal.mlkit_vision_common.Z3;
import com.google.android.material.floatingactionbutton.FloatingActionButton;

/* loaded from: classes2.dex */
public final class c extends Z3 {
    public final /* synthetic */ int b;
    public final /* synthetic */ BottomAppBar c;

    public c(BottomAppBar bottomAppBar, int i) {
        this.c = bottomAppBar;
        this.b = i;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_common.Z3
    public final void a(FloatingActionButton floatingActionButton) {
        int i = BottomAppBar.E1;
        floatingActionButton.setTranslationX(this.c.E(this.b));
        floatingActionButton.l(new b(this), true);
    }
}
