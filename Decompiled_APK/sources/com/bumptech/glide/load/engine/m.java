package com.bumptech.glide.load.engine;

import java.util.concurrent.Executor;

/* loaded from: classes.dex */
public final class m {
    public final com.bumptech.glide.request.g a;
    public final Executor b;

    public m(com.bumptech.glide.request.g gVar, Executor executor) {
        this.a = gVar;
        this.b = executor;
    }

    public final boolean equals(Object obj) {
        if (obj instanceof m) {
            return this.a.equals(((m) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }
}
