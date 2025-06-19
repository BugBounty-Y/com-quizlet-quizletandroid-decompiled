package com.bumptech.glide.manager;

import android.view.View;
import androidx.fragment.app.I;
import java.util.Collections;
import java.util.Set;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public final class e implements f {
    public final Set a = Collections.newSetFromMap(new WeakHashMap());
    public volatile boolean b;

    @Override // com.bumptech.glide.manager.f
    public final void c(I i) {
        if (!this.b && this.a.add(i)) {
            View decorView = i.getWindow().getDecorView();
            decorView.getViewTreeObserver().addOnDrawListener(new d(this, decorView));
        }
    }
}
