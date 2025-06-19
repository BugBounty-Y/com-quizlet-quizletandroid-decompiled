package com.bumptech.glide.load.model;

import android.content.Context;
import android.net.Uri;

/* loaded from: classes.dex */
public final class m implements r {
    public final Context a;

    public static final class a implements s {
        public final Context a;

        public a(Context context) {
            this.a = context;
        }

        @Override // com.bumptech.glide.load.model.s
        public final r a(x xVar) {
            return new m(this.a);
        }
    }

    public m(Context context) {
        this.a = context;
    }

    @Override // com.bumptech.glide.load.model.r
    public final boolean a(Object obj) {
        return com.google.android.gms.internal.mlkit_vision_common.A.e((Uri) obj);
    }

    @Override // com.bumptech.glide.load.model.r
    public final q b(Object obj, int i, int i2, com.bumptech.glide.load.h hVar) {
        Uri uri = (Uri) obj;
        return new q(new com.bumptech.glide.signature.b(uri), new n(0, this.a, uri));
    }
}
