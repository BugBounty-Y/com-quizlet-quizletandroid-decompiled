package com.lyft.android.scissors;

import android.net.Uri;
import android.view.ViewTreeObserver;

/* loaded from: classes2.dex */
public final class d implements ViewTreeObserver.OnGlobalLayoutListener {
    public final /* synthetic */ Uri a;
    public final /* synthetic */ e b;

    public d(e eVar, Uri uri) {
        this.b = eVar;
        this.a = uri;
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public final void onGlobalLayout() {
        e eVar = this.b;
        CropView cropView = (CropView) eVar.a;
        if (cropView.getViewTreeObserver().isAlive()) {
            cropView.getViewTreeObserver().removeGlobalOnLayoutListener(this);
        }
        eVar.b(this.a);
    }
}
