package com.bumptech.glide.load.engine.bitmap_recycle;

import android.graphics.Bitmap;
import com.bumptech.glide.util.m;

/* loaded from: classes.dex */
public final class i implements g {
    public final e a;
    public int b;
    public Bitmap.Config c;

    public i(e eVar) {
        this.a = eVar;
    }

    @Override // com.bumptech.glide.load.engine.bitmap_recycle.g
    public final void a() {
        this.a.J(this);
    }

    public final boolean equals(Object obj) {
        if (obj instanceof i) {
            i iVar = (i) obj;
            if (this.b == iVar.b && m.b(this.c, iVar.c)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        int i = this.b * 31;
        Bitmap.Config config = this.c;
        return i + (config != null ? config.hashCode() : 0);
    }

    public final String toString() {
        return j.c(this.b, this.c);
    }
}
