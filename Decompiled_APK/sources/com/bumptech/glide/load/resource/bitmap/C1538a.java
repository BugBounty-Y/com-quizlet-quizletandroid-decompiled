package com.bumptech.glide.load.resource.bitmap;

import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import java.io.InputStream;
import java.util.ArrayDeque;

/* renamed from: com.bumptech.glide.load.resource.bitmap.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1538a implements com.bumptech.glide.load.j {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;

    public /* synthetic */ C1538a(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // com.bumptech.glide.load.j
    public final boolean a(Object obj, com.bumptech.glide.load.h hVar) {
        switch (this.a) {
            case 0:
                return ((com.bumptech.glide.load.j) this.b).a(obj, hVar);
            case 1:
                return "android.resource".equals(((Uri) obj).getScheme());
            default:
                return true;
        }
    }

    @Override // com.bumptech.glide.load.j
    public final com.bumptech.glide.load.engine.v b(Object obj, int i, int i2, com.bumptech.glide.load.h hVar) throws PackageManager.NameNotFoundException, NumberFormatException {
        boolean z;
        w wVar;
        com.bumptech.glide.util.e eVar;
        switch (this.a) {
            case 0:
                com.bumptech.glide.load.engine.v vVarB = ((com.bumptech.glide.load.j) this.b).b(obj, i, i2, hVar);
                if (vVarB == null) {
                    return null;
                }
                return new C1541d((Resources) this.c, vVarB);
            case 1:
                com.bumptech.glide.load.engine.v vVarC = ((com.bumptech.glide.load.resource.drawable.c) this.b).c((Uri) obj, hVar);
                if (vVarC == null) {
                    return null;
                }
                return q.a((com.bumptech.glide.load.engine.bitmap_recycle.a) this.c, (Drawable) ((com.bumptech.glide.load.resource.drawable.b) vVarC).get(), i, i2);
            default:
                InputStream inputStream = (InputStream) obj;
                if (inputStream instanceof w) {
                    wVar = (w) inputStream;
                    z = false;
                } else {
                    z = true;
                    wVar = new w(inputStream, (androidx.compose.foundation.lazy.grid.m) this.c);
                }
                ArrayDeque arrayDeque = com.bumptech.glide.util.e.c;
                synchronized (arrayDeque) {
                    eVar = (com.bumptech.glide.util.e) arrayDeque.poll();
                }
                if (eVar == null) {
                    eVar = new com.bumptech.glide.util.e();
                }
                com.bumptech.glide.util.e eVar2 = eVar;
                eVar2.a = wVar;
                com.bumptech.glide.util.j jVar = new com.bumptech.glide.util.j(eVar2);
                com.quizlet.data.repository.widget.b bVar = new com.quizlet.data.repository.widget.b(wVar, false, eVar2, 7);
                try {
                    o oVar = (o) this.b;
                    C1541d c1541dA = oVar.a(new com.google.android.gms.internal.appset.e(jVar, oVar.d, oVar.c), i, i2, hVar, bVar);
                    eVar2.b = null;
                    eVar2.a = null;
                    synchronized (arrayDeque) {
                        arrayDeque.offer(eVar2);
                    }
                    if (z) {
                        wVar.d();
                    }
                    return c1541dA;
                } catch (Throwable th) {
                    eVar2.b = null;
                    eVar2.a = null;
                    ArrayDeque arrayDeque2 = com.bumptech.glide.util.e.c;
                    synchronized (arrayDeque2) {
                        arrayDeque2.offer(eVar2);
                        if (!z) {
                            throw th;
                        }
                        wVar.d();
                        throw th;
                    }
                }
        }
    }

    public C1538a(Resources resources, com.bumptech.glide.load.j jVar) {
        this.a = 0;
        this.c = resources;
        this.b = jVar;
    }
}
