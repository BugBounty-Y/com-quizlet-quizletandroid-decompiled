package com.bumptech.glide.load.resource.drawable;

import android.graphics.Bitmap;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import androidx.compose.foundation.lazy.grid.m;
import com.bumptech.glide.gifdecoder.d;
import com.bumptech.glide.load.engine.s;
import com.bumptech.glide.load.engine.v;
import com.bumptech.glide.load.resource.gif.g;
import com.bumptech.glide.util.f;

/* loaded from: classes.dex */
public final class b implements v, s {
    public final Drawable a;
    public final /* synthetic */ int b;

    public b(Drawable drawable, int i) {
        this.b = i;
        f.c(drawable, "Argument must not be null");
        this.a = drawable;
    }

    private final void d() {
    }

    @Override // com.bumptech.glide.load.engine.v
    public final int a() {
        switch (this.b) {
            case 0:
                Drawable drawable = this.a;
                return Math.max(1, drawable.getIntrinsicHeight() * drawable.getIntrinsicWidth() * 4);
            default:
                g gVar = (g) ((com.bumptech.glide.load.resource.gif.b) this.a).a.b;
                d dVar = gVar.a;
                return (dVar.j.length * 4) + dVar.d.limit() + dVar.i.length + gVar.n;
        }
    }

    @Override // com.bumptech.glide.load.engine.s
    public void b() {
        switch (this.b) {
            case 1:
                ((g) ((com.bumptech.glide.load.resource.gif.b) this.a).a.b).l.prepareToDraw();
                break;
            default:
                Drawable drawable = this.a;
                if (!(drawable instanceof BitmapDrawable)) {
                    if (drawable instanceof com.bumptech.glide.load.resource.gif.b) {
                        ((g) ((com.bumptech.glide.load.resource.gif.b) drawable).a.b).l.prepareToDraw();
                        break;
                    }
                } else {
                    ((BitmapDrawable) drawable).getBitmap().prepareToDraw();
                    break;
                }
                break;
        }
    }

    @Override // com.bumptech.glide.load.engine.v
    public final Class c() {
        switch (this.b) {
            case 0:
                return this.a.getClass();
            default:
                return com.bumptech.glide.load.resource.gif.b.class;
        }
    }

    @Override // com.bumptech.glide.load.engine.v
    public final Object get() {
        Drawable drawable = this.a;
        Drawable.ConstantState constantState = drawable.getConstantState();
        return constantState == null ? drawable : constantState.newDrawable();
    }

    @Override // com.bumptech.glide.load.engine.v
    public final void recycle() {
        m mVar;
        m mVar2;
        m mVar3;
        switch (this.b) {
            case 0:
                break;
            default:
                com.bumptech.glide.load.resource.gif.b bVar = (com.bumptech.glide.load.resource.gif.b) this.a;
                bVar.stop();
                bVar.d = true;
                g gVar = (g) bVar.a.b;
                gVar.c.clear();
                Bitmap bitmap = gVar.l;
                if (bitmap != null) {
                    gVar.e.b(bitmap);
                    gVar.l = null;
                }
                gVar.f = false;
                com.bumptech.glide.load.resource.gif.d dVar = gVar.i;
                com.bumptech.glide.m mVar4 = gVar.d;
                if (dVar != null) {
                    mVar4.i(dVar);
                    gVar.i = null;
                }
                com.bumptech.glide.load.resource.gif.d dVar2 = gVar.k;
                if (dVar2 != null) {
                    mVar4.i(dVar2);
                    gVar.k = null;
                }
                com.bumptech.glide.load.resource.gif.d dVar3 = gVar.m;
                if (dVar3 != null) {
                    mVar4.i(dVar3);
                    gVar.m = null;
                }
                d dVar4 = gVar.a;
                dVar4.l = null;
                byte[] bArr = dVar4.i;
                androidx.work.impl.model.c cVar = dVar4.c;
                if (bArr != null && (mVar3 = (m) cVar.c) != null) {
                    mVar3.k(bArr);
                }
                int[] iArr = dVar4.j;
                if (iArr != null && (mVar2 = (m) cVar.c) != null) {
                    mVar2.k(iArr);
                }
                Bitmap bitmap2 = dVar4.m;
                if (bitmap2 != null) {
                    ((com.bumptech.glide.load.engine.bitmap_recycle.a) cVar.b).b(bitmap2);
                }
                dVar4.m = null;
                dVar4.d = null;
                dVar4.s = null;
                byte[] bArr2 = dVar4.e;
                if (bArr2 != null && (mVar = (m) cVar.c) != null) {
                    mVar.k(bArr2);
                }
                gVar.j = true;
                break;
        }
    }
}
