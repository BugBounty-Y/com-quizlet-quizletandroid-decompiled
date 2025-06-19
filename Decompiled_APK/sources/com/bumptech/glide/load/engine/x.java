package com.bumptech.glide.load.engine;

import androidx.camera.camera2.internal.C0148z;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.ArrayDeque;

/* loaded from: classes.dex */
public final class x implements com.bumptech.glide.load.e {
    public static final C0148z j = new C0148z(1, 50);
    public final androidx.compose.foundation.lazy.grid.m b;
    public final com.bumptech.glide.load.e c;
    public final com.bumptech.glide.load.e d;
    public final int e;
    public final int f;
    public final Class g;
    public final com.bumptech.glide.load.h h;
    public final com.bumptech.glide.load.l i;

    public x(androidx.compose.foundation.lazy.grid.m mVar, com.bumptech.glide.load.e eVar, com.bumptech.glide.load.e eVar2, int i, int i2, com.bumptech.glide.load.l lVar, Class cls, com.bumptech.glide.load.h hVar) {
        this.b = mVar;
        this.c = eVar;
        this.d = eVar2;
        this.e = i;
        this.f = i2;
        this.i = lVar;
        this.g = cls;
        this.h = hVar;
    }

    @Override // com.bumptech.glide.load.e
    public final void a(MessageDigest messageDigest) {
        Object objI;
        androidx.compose.foundation.lazy.grid.m mVar = this.b;
        synchronized (mVar) {
            com.bumptech.glide.load.engine.bitmap_recycle.e eVar = (com.bumptech.glide.load.engine.bitmap_recycle.e) mVar.d;
            com.bumptech.glide.load.engine.bitmap_recycle.g gVarT = (com.bumptech.glide.load.engine.bitmap_recycle.g) ((ArrayDeque) eVar.b).poll();
            if (gVarT == null) {
                gVarT = eVar.T();
            }
            com.bumptech.glide.load.engine.bitmap_recycle.d dVar = (com.bumptech.glide.load.engine.bitmap_recycle.d) gVarT;
            dVar.b = 8;
            dVar.c = byte[].class;
            objI = mVar.i(dVar, byte[].class);
        }
        byte[] bArr = (byte[]) objI;
        ByteBuffer.wrap(bArr).putInt(this.e).putInt(this.f).array();
        this.d.a(messageDigest);
        this.c.a(messageDigest);
        messageDigest.update(bArr);
        com.bumptech.glide.load.l lVar = this.i;
        if (lVar != null) {
            lVar.a(messageDigest);
        }
        this.h.a(messageDigest);
        C0148z c0148z = j;
        Class cls = this.g;
        byte[] bytes = (byte[]) c0148z.a(cls);
        if (bytes == null) {
            bytes = cls.getName().getBytes(com.bumptech.glide.load.e.a);
            c0148z.f(cls, bytes);
        }
        messageDigest.update(bytes);
        this.b.k(bArr);
    }

    @Override // com.bumptech.glide.load.e
    public final boolean equals(Object obj) {
        if (obj instanceof x) {
            x xVar = (x) obj;
            if (this.f == xVar.f && this.e == xVar.e && com.bumptech.glide.util.m.b(this.i, xVar.i) && this.g.equals(xVar.g) && this.c.equals(xVar.c) && this.d.equals(xVar.d) && this.h.equals(xVar.h)) {
                return true;
            }
        }
        return false;
    }

    @Override // com.bumptech.glide.load.e
    public final int hashCode() {
        int iHashCode = ((((this.d.hashCode() + (this.c.hashCode() * 31)) * 31) + this.e) * 31) + this.f;
        com.bumptech.glide.load.l lVar = this.i;
        if (lVar != null) {
            iHashCode = (iHashCode * 31) + lVar.hashCode();
        }
        return this.h.b.hashCode() + ((this.g.hashCode() + (iHashCode * 31)) * 31);
    }

    public final String toString() {
        return "ResourceCacheKey{sourceKey=" + this.c + ", signature=" + this.d + ", width=" + this.e + ", height=" + this.f + ", decodedResourceClass=" + this.g + ", transformation='" + this.i + "', options=" + this.h + '}';
    }
}
