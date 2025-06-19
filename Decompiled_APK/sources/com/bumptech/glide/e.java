package com.bumptech.glide;

import android.content.Context;
import android.content.ContextWrapper;
import androidx.appcompat.app.L;
import androidx.collection.C0208f;
import java.util.List;

/* loaded from: classes.dex */
public final class e extends ContextWrapper {
    public static final a k;
    public final androidx.compose.foundation.lazy.grid.m a;
    public final com.bumptech.glide.load.engine.k b;
    public final com.google.mlkit.common.sdkinternal.b c;
    public final com.quizlet.shared.usecase.studiableMetadata.a d;
    public final List e;
    public final C0208f f;
    public final com.bumptech.glide.load.engine.l g;
    public final L h;
    public final int i;
    public com.bumptech.glide.request.f j;

    static {
        a aVar = new a();
        aVar.a = com.bumptech.glide.request.transition.b.a;
        k = aVar;
    }

    public e(Context context, androidx.compose.foundation.lazy.grid.m mVar, androidx.browser.customtabs.k kVar, com.google.mlkit.common.sdkinternal.b bVar, com.quizlet.shared.usecase.studiableMetadata.a aVar, C0208f c0208f, List list, com.bumptech.glide.load.engine.l lVar, L l, int i) {
        super(context.getApplicationContext());
        this.a = mVar;
        this.c = bVar;
        this.d = aVar;
        this.e = list;
        this.f = c0208f;
        this.g = lVar;
        this.h = l;
        this.i = i;
        this.b = new com.bumptech.glide.load.engine.k(kVar);
    }

    public final h a() {
        return (h) this.b.get();
    }
}
