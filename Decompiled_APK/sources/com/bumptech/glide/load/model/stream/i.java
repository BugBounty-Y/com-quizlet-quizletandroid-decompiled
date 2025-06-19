package com.bumptech.glide.load.model.stream;

import android.content.Context;
import android.net.Uri;
import android.os.Build;
import com.bumptech.glide.load.model.q;
import com.bumptech.glide.load.model.r;
import com.google.android.gms.internal.mlkit_vision_common.A;

/* loaded from: classes.dex */
public final class i implements r {
    public final Context a;
    public final r b;
    public final r c;
    public final Class d;

    public i(Context context, r rVar, r rVar2, Class cls) {
        this.a = context.getApplicationContext();
        this.b = rVar;
        this.c = rVar2;
        this.d = cls;
    }

    @Override // com.bumptech.glide.load.model.r
    public final boolean a(Object obj) {
        return Build.VERSION.SDK_INT >= 29 && A.e((Uri) obj);
    }

    @Override // com.bumptech.glide.load.model.r
    public final q b(Object obj, int i, int i2, com.bumptech.glide.load.h hVar) {
        Uri uri = (Uri) obj;
        return new q(new com.bumptech.glide.signature.b(uri), new h(this.a, this.b, this.c, uri, i, i2, hVar, this.d));
    }
}
