package com.bumptech.glide.gifdecoder;

import android.graphics.Bitmap;
import android.util.Log;
import androidx.compose.foundation.lazy.grid.m;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class d {
    public int[] a;
    public final androidx.work.impl.model.c c;
    public ByteBuffer d;
    public byte[] e;
    public short[] f;
    public byte[] g;
    public byte[] h;
    public byte[] i;
    public final int[] j;
    public int k;
    public b l;
    public Bitmap m;
    public final boolean n;
    public int o;
    public final int p;
    public final int q;
    public final int r;
    public Boolean s;
    public final int[] b = new int[256];
    public Bitmap.Config t = Bitmap.Config.ARGB_8888;

    public d(androidx.work.impl.model.c cVar, b bVar, ByteBuffer byteBuffer, int i) {
        this.c = cVar;
        this.l = new b();
        synchronized (this) {
            try {
                if (i <= 0) {
                    throw new IllegalArgumentException("Sample size must be >=0, not: " + i);
                }
                int iHighestOneBit = Integer.highestOneBit(i);
                this.o = 0;
                this.l = bVar;
                this.k = -1;
                ByteBuffer byteBufferAsReadOnlyBuffer = byteBuffer.asReadOnlyBuffer();
                this.d = byteBufferAsReadOnlyBuffer;
                byteBufferAsReadOnlyBuffer.position(0);
                this.d.order(ByteOrder.LITTLE_ENDIAN);
                this.n = false;
                Iterator it2 = bVar.e.iterator();
                while (true) {
                    if (!it2.hasNext()) {
                        break;
                    } else if (((a) it2.next()).g == 3) {
                        this.n = true;
                        break;
                    }
                }
                this.p = iHighestOneBit;
                int i2 = bVar.f;
                this.r = i2 / iHighestOneBit;
                int i3 = bVar.g;
                this.q = i3 / iHighestOneBit;
                int i4 = i2 * i3;
                m mVar = (m) this.c.c;
                this.i = mVar == null ? new byte[i4] : (byte[]) mVar.f(i4, byte[].class);
                androidx.work.impl.model.c cVar2 = this.c;
                int i5 = this.r * this.q;
                m mVar2 = (m) cVar2.c;
                this.j = mVar2 == null ? new int[i5] : (int[]) mVar2.f(i5, int[].class);
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final Bitmap a() {
        Boolean bool = this.s;
        Bitmap bitmapA = ((com.bumptech.glide.load.engine.bitmap_recycle.a) this.c.b).a(this.r, this.q, (bool == null || bool.booleanValue()) ? Bitmap.Config.ARGB_8888 : this.t);
        bitmapA.setHasAlpha(true);
        return bitmapA;
    }

    public final synchronized Bitmap b() {
        try {
            if (this.l.c <= 0 || this.k < 0) {
                if (Log.isLoggable("d", 3)) {
                    int i = this.l.c;
                }
                this.o = 1;
            }
            int i2 = this.o;
            if (i2 != 1 && i2 != 2) {
                this.o = 0;
                if (this.e == null) {
                    m mVar = (m) this.c.c;
                    this.e = mVar == null ? new byte[255] : (byte[]) mVar.f(255, byte[].class);
                }
                a aVar = (a) this.l.e.get(this.k);
                int i3 = this.k - 1;
                a aVar2 = i3 >= 0 ? (a) this.l.e.get(i3) : null;
                int[] iArr = aVar.k;
                if (iArr == null) {
                    iArr = this.l.a;
                }
                this.a = iArr;
                if (iArr == null) {
                    Log.isLoggable("d", 3);
                    this.o = 1;
                    return null;
                }
                if (aVar.f) {
                    System.arraycopy(iArr, 0, this.b, 0, iArr.length);
                    int[] iArr2 = this.b;
                    this.a = iArr2;
                    iArr2[aVar.h] = 0;
                    if (aVar.g == 2 && this.k == 0) {
                        this.s = Boolean.TRUE;
                    }
                }
                return d(aVar, aVar2);
            }
            Log.isLoggable("d", 3);
            return null;
        } catch (Throwable th) {
            throw th;
        }
    }

    public final void c(Bitmap.Config config) {
        Bitmap.Config config2;
        Bitmap.Config config3 = Bitmap.Config.ARGB_8888;
        if (config == config3 || config == (config2 = Bitmap.Config.RGB_565)) {
            this.t = config;
            return;
        }
        throw new IllegalArgumentException("Unsupported format: " + config + ", must be one of " + config3 + " or " + config2);
    }

    /* JADX WARN: Removed duplicated region for block: B:26:0x0047  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.graphics.Bitmap d(com.bumptech.glide.gifdecoder.a r35, com.bumptech.glide.gifdecoder.a r36) {
        /*
            Method dump skipped, instructions count: 1044
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.bumptech.glide.gifdecoder.d.d(com.bumptech.glide.gifdecoder.a, com.bumptech.glide.gifdecoder.a):android.graphics.Bitmap");
    }
}
