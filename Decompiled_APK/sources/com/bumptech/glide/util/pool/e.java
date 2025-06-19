package com.bumptech.glide.util.pool;

/* loaded from: classes.dex */
public final class e {
    public volatile boolean a;

    public final void a() {
        if (this.a) {
            throw new IllegalStateException("Already released");
        }
    }
}
