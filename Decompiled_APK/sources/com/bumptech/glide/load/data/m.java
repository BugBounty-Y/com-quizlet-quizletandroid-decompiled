package com.bumptech.glide.load.data;

import java.io.InputStream;

/* loaded from: classes.dex */
public final class m implements f {
    public final androidx.compose.foundation.lazy.grid.m a;

    public m(androidx.compose.foundation.lazy.grid.m mVar) {
        this.a = mVar;
    }

    @Override // com.bumptech.glide.load.data.f
    public final g a(Object obj) {
        return new i((InputStream) obj, this.a);
    }

    @Override // com.bumptech.glide.load.data.f
    public final Class getDataClass() {
        return InputStream.class;
    }
}
