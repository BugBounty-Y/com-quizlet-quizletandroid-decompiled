package com.bumptech.glide.load.resource.gif;

import android.content.Context;
import android.graphics.Bitmap;
import com.bumptech.glide.Glide;
import com.bumptech.glide.load.engine.v;
import com.bumptech.glide.load.l;
import com.bumptech.glide.load.resource.bitmap.C1541d;
import java.security.MessageDigest;

/* loaded from: classes.dex */
public final class c implements l {
    public final l b;

    public c(l lVar) {
        com.bumptech.glide.util.f.c(lVar, "Argument must not be null");
        this.b = lVar;
    }

    @Override // com.bumptech.glide.load.e
    public final void a(MessageDigest messageDigest) {
        this.b.a(messageDigest);
    }

    @Override // com.bumptech.glide.load.l
    public final v b(Context context, v vVar, int i, int i2) {
        b bVar = (b) vVar.get();
        v c1541d = new C1541d(((g) bVar.a.b).l, Glide.a(context).a);
        l lVar = this.b;
        v vVarB = lVar.b(context, c1541d, i, i2);
        if (!c1541d.equals(vVarB)) {
            c1541d.recycle();
        }
        ((g) bVar.a.b).c(lVar, (Bitmap) vVarB.get());
        return vVar;
    }

    @Override // com.bumptech.glide.load.e
    public final boolean equals(Object obj) {
        if (obj instanceof c) {
            return this.b.equals(((c) obj).b);
        }
        return false;
    }

    @Override // com.bumptech.glide.load.e
    public final int hashCode() {
        return this.b.hashCode();
    }
}
