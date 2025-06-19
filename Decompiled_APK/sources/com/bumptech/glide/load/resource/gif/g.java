package com.bumptech.glide.load.resource.gif;

import android.graphics.Bitmap;
import android.graphics.drawable.Drawable;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import com.bumptech.glide.Glide;
import com.bumptech.glide.k;
import com.bumptech.glide.load.engine.j;
import com.bumptech.glide.load.l;
import com.bumptech.glide.m;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class g {
    public final com.bumptech.glide.gifdecoder.d a;
    public final Handler b;
    public final ArrayList c;
    public final m d;
    public final com.bumptech.glide.load.engine.bitmap_recycle.a e;
    public boolean f;
    public boolean g;
    public k h;
    public d i;
    public boolean j;
    public d k;
    public Bitmap l;
    public d m;
    public int n;
    public int o;
    public int p;

    public g(Glide glide, com.bumptech.glide.gifdecoder.d dVar, int i, int i2, Bitmap bitmap) {
        com.bumptech.glide.load.resource.d dVar2 = com.bumptech.glide.load.resource.d.b;
        com.bumptech.glide.load.engine.bitmap_recycle.a aVar = glide.a;
        com.bumptech.glide.e eVar = glide.c;
        m mVarC = Glide.c(eVar.getBaseContext());
        m mVarC2 = Glide.c(eVar.getBaseContext());
        mVarC2.getClass();
        k kVarB = new k(mVarC2.a, mVarC2, Bitmap.class, mVarC2.b).b(m.k).b(((com.bumptech.glide.request.f) ((com.bumptech.glide.request.f) ((com.bumptech.glide.request.f) new com.bumptech.glide.request.f().e(j.b)).u()).q()).i(i, i2));
        this.c = new ArrayList();
        this.d = mVarC;
        Handler handler = new Handler(Looper.getMainLooper(), new f(this, 0));
        this.e = aVar;
        this.b = handler;
        this.h = kVarB;
        this.a = dVar;
        c(dVar2, bitmap);
    }

    public final void a() {
        int i;
        if (!this.f || this.g) {
            return;
        }
        d dVar = this.m;
        if (dVar != null) {
            this.m = null;
            b(dVar);
            return;
        }
        this.g = true;
        com.bumptech.glide.gifdecoder.d dVar2 = this.a;
        int i2 = dVar2.l.c;
        long jUptimeMillis = SystemClock.uptimeMillis() + ((i2 <= 0 || (i = dVar2.k) < 0) ? 0 : (i < 0 || i >= i2) ? -1 : ((com.bumptech.glide.gifdecoder.a) r2.e.get(i)).i);
        int i3 = (dVar2.k + 1) % dVar2.l.c;
        dVar2.k = i3;
        this.k = new d(this.b, i3, jUptimeMillis);
        k kVarD = this.h.b((com.bumptech.glide.request.f) new com.bumptech.glide.request.f().p(new com.bumptech.glide.signature.b(Double.valueOf(Math.random())))).D(dVar2);
        kVarD.A(this.k, kVarD);
    }

    public final void b(d dVar) {
        this.g = false;
        boolean z = this.j;
        Handler handler = this.b;
        if (z) {
            handler.obtainMessage(2, dVar).sendToTarget();
            return;
        }
        if (!this.f) {
            this.m = dVar;
            return;
        }
        if (dVar.g != null) {
            Bitmap bitmap = this.l;
            if (bitmap != null) {
                this.e.b(bitmap);
                this.l = null;
            }
            d dVar2 = this.i;
            this.i = dVar;
            ArrayList arrayList = this.c;
            for (int size = arrayList.size() - 1; size >= 0; size--) {
                b bVar = (b) ((e) arrayList.get(size));
                Object callback = bVar.getCallback();
                while (callback instanceof Drawable) {
                    callback = ((Drawable) callback).getCallback();
                }
                if (callback == null) {
                    bVar.stop();
                    bVar.invalidateSelf();
                } else {
                    bVar.invalidateSelf();
                    d dVar3 = ((g) bVar.a.b).i;
                    if ((dVar3 != null ? dVar3.e : -1) == r5.a.l.c - 1) {
                        bVar.f++;
                    }
                    int i = bVar.g;
                    if (i != -1 && bVar.f >= i) {
                        bVar.stop();
                    }
                }
            }
            if (dVar2 != null) {
                handler.obtainMessage(2, dVar2).sendToTarget();
            }
        }
        a();
    }

    public final void c(l lVar, Bitmap bitmap) {
        com.bumptech.glide.util.f.c(lVar, "Argument must not be null");
        com.bumptech.glide.util.f.c(bitmap, "Argument must not be null");
        this.l = bitmap;
        this.h = this.h.b(new com.bumptech.glide.request.f().r(lVar, true));
        this.n = com.bumptech.glide.util.m.c(bitmap);
        this.o = bitmap.getWidth();
        this.p = bitmap.getHeight();
    }
}
