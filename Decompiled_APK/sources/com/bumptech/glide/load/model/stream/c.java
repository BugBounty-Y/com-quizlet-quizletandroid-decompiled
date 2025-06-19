package com.bumptech.glide.load.model.stream;

import android.content.Context;
import android.net.Uri;
import com.bumptech.glide.load.model.q;
import com.bumptech.glide.load.model.r;
import com.bumptech.glide.load.model.s;
import com.bumptech.glide.load.model.x;
import com.bumptech.glide.load.resource.bitmap.F;
import com.google.android.gms.internal.mlkit_vision_common.A;

/* loaded from: classes.dex */
public class c implements r {
    public final Context a;

    public static class a implements s {
        public final Context a;

        public a(Context context) {
            this.a = context;
        }

        @Override // com.bumptech.glide.load.model.s
        public final r a(x xVar) {
            return new c(this.a);
        }
    }

    public c(Context context) {
        this.a = context.getApplicationContext();
    }

    @Override // com.bumptech.glide.load.model.r
    public final boolean a(Object obj) {
        Uri uri = (Uri) obj;
        return A.e(uri) && uri.getPathSegments().contains(com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_VIDEO);
    }

    @Override // com.bumptech.glide.load.model.r
    public final q b(Object obj, int i, int i2, com.bumptech.glide.load.h hVar) {
        Long l;
        Uri uri = (Uri) obj;
        if (i == Integer.MIN_VALUE || i2 == Integer.MIN_VALUE || i > 512 || i2 > 384 || (l = (Long) hVar.c(F.d)) == null || l.longValue() != -1) {
            return null;
        }
        com.bumptech.glide.signature.b bVar = new com.bumptech.glide.signature.b(uri);
        Context context = this.a;
        return new q(bVar, com.bumptech.glide.load.data.mediastore.b.a(context, uri, new com.bumptech.glide.load.data.mediastore.a(context.getContentResolver(), 1)));
    }
}
