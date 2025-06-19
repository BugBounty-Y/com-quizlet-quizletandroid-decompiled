package com.bumptech.glide.load.engine.cache;

import java.security.MessageDigest;

/* loaded from: classes.dex */
public final class g implements com.bumptech.glide.util.pool.b {
    public final MessageDigest a;
    public final com.bumptech.glide.util.pool.e b = new com.bumptech.glide.util.pool.e();

    public g(MessageDigest messageDigest) {
        this.a = messageDigest;
    }

    @Override // com.bumptech.glide.util.pool.b
    public final com.bumptech.glide.util.pool.e b() {
        return this.b;
    }
}
