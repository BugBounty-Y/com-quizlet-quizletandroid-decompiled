package com.bumptech.glide.load.engine;

/* loaded from: classes.dex */
public final class b extends RuntimeException {
    public b(Throwable th) {
        super("Unexpected exception thrown by non-Glide code", th);
    }
}
