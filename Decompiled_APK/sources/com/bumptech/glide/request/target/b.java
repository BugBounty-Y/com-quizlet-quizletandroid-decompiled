package com.bumptech.glide.request.target;

import android.graphics.drawable.Drawable;
import com.bumptech.glide.request.g;
import com.bumptech.glide.util.m;

/* loaded from: classes.dex */
public abstract class b implements e {
    public final int a;
    public final int b;
    public com.bumptech.glide.request.c c;

    public b() {
        if (!m.i(Integer.MIN_VALUE, Integer.MIN_VALUE)) {
            throw new IllegalArgumentException("Width and height must both be > 0 or Target#SIZE_ORIGINAL, but given width: -2147483648 and height: -2147483648");
        }
        this.a = Integer.MIN_VALUE;
        this.b = Integer.MIN_VALUE;
    }

    @Override // com.bumptech.glide.request.target.e
    public final com.bumptech.glide.request.c b() {
        return this.c;
    }

    @Override // com.bumptech.glide.request.target.e
    public final void c(g gVar) {
    }

    @Override // com.bumptech.glide.request.target.e
    public final void d(com.bumptech.glide.request.c cVar) {
        this.c = cVar;
    }

    @Override // com.bumptech.glide.request.target.e
    public final void e(g gVar) throws Throwable {
        gVar.k(this.a, this.b);
    }

    @Override // com.bumptech.glide.request.target.e
    public final void f(Drawable drawable) {
    }

    @Override // com.bumptech.glide.request.target.e
    public final void g(Drawable drawable) {
    }

    @Override // com.bumptech.glide.manager.i
    public final void onDestroy() {
    }

    @Override // com.bumptech.glide.manager.i
    public final void onStart() {
    }

    @Override // com.bumptech.glide.manager.i
    public final void onStop() {
    }
}
