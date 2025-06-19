package com.bumptech.glide.load.resource.bitmap;

import android.content.Context;
import android.graphics.drawable.Drawable;
import com.bumptech.glide.Glide;
import java.security.MessageDigest;

/* loaded from: classes.dex */
public final class r implements com.bumptech.glide.load.l {
    public final com.bumptech.glide.load.l b;
    public final boolean c;

    public r(com.bumptech.glide.load.l lVar, boolean z) {
        this.b = lVar;
        this.c = z;
    }

    @Override // com.bumptech.glide.load.e
    public final void a(MessageDigest messageDigest) {
        this.b.a(messageDigest);
    }

    @Override // com.bumptech.glide.load.l
    public final com.bumptech.glide.load.engine.v b(Context context, com.bumptech.glide.load.engine.v vVar, int i, int i2) {
        com.bumptech.glide.load.engine.bitmap_recycle.a aVar = Glide.a(context).a;
        Drawable drawable = (Drawable) vVar.get();
        C1541d c1541dA = q.a(aVar, drawable, i, i2);
        if (c1541dA != null) {
            com.bumptech.glide.load.engine.v vVarB = this.b.b(context, c1541dA, i, i2);
            if (!vVarB.equals(c1541dA)) {
                return new C1541d(context.getResources(), vVarB);
            }
            vVarB.recycle();
            return vVar;
        }
        if (!this.c) {
            return vVar;
        }
        throw new IllegalArgumentException("Unable to convert " + drawable + " to a Bitmap");
    }

    @Override // com.bumptech.glide.load.e
    public final boolean equals(Object obj) {
        if (obj instanceof r) {
            return this.b.equals(((r) obj).b);
        }
        return false;
    }

    @Override // com.bumptech.glide.load.e
    public final int hashCode() {
        return this.b.hashCode();
    }
}
