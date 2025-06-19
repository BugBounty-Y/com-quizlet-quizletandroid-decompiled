package com.lyft.android.scissors;

import android.graphics.Bitmap;
import android.net.Uri;
import android.widget.ImageView;
import com.bumptech.glide.Glide;
import java.util.concurrent.ExecutorService;

/* loaded from: classes2.dex */
public final class e implements a {
    public final Object a;
    public Object b;

    public e(com.bumptech.glide.m mVar, g gVar) {
        this.a = mVar;
        this.b = gVar;
    }

    @Override // com.lyft.android.scissors.a
    public void a(Uri uri, ImageView imageView) {
        com.bumptech.glide.request.f fVar = new com.bumptech.glide.request.f();
        ((com.bumptech.glide.request.f) ((com.bumptech.glide.request.f) fVar.q()).e(com.bumptech.glide.load.engine.j.c)).r((g) this.b, true);
        com.bumptech.glide.m mVar = (com.bumptech.glide.m) this.a;
        mVar.getClass();
        new com.bumptech.glide.k(mVar.a, mVar, Bitmap.class, mVar.b).b(com.bumptech.glide.m.k).D(uri).b(fVar).z(imageView);
    }

    public void b(Uri uri) {
        Object objB;
        a aVar = (a) this.b;
        CropView cropView = (CropView) this.a;
        if (aVar == null) {
            if (f.a) {
                objB = h.b(cropView);
            } else if (f.b) {
                objB = new e(Glide.c(cropView.getContext()), new g(cropView.getViewportWidth(), cropView.getViewportHeight()));
            } else {
                if (!f.c) {
                    throw new IllegalStateException("You must provide a BitmapLoader.");
                }
                objB = l.b(cropView);
            }
            this.b = objB;
        }
        ((a) this.b).a(uri, cropView);
    }

    public e(CropView cropView) {
        ExecutorService executorService = n.a;
        if (cropView != null) {
            this.a = cropView;
            return;
        }
        throw new NullPointerException("cropView == null");
    }
}
