package com.bumptech.glide.load.engine.bitmap_recycle;

import android.graphics.Bitmap;
import android.util.Log;
import com.bumptech.glide.util.m;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/* loaded from: classes.dex */
public final class f implements a {
    public static final Bitmap.Config f = Bitmap.Config.ARGB_8888;
    public final j a;
    public final Set b;
    public final com.google.mlkit.common.sdkinternal.b c;
    public final long d;
    public long e;

    public f(long j) {
        j jVar = new j();
        HashSet hashSet = new HashSet(Arrays.asList(Bitmap.Config.values()));
        hashSet.add(null);
        hashSet.remove(Bitmap.Config.HARDWARE);
        Set setUnmodifiableSet = Collections.unmodifiableSet(hashSet);
        this.d = j;
        this.a = jVar;
        this.b = setUnmodifiableSet;
        this.c = new com.google.mlkit.common.sdkinternal.b(6);
    }

    @Override // com.bumptech.glide.load.engine.bitmap_recycle.a
    public final Bitmap a(int i, int i2, Bitmap.Config config) {
        Bitmap bitmapF = f(i, i2, config);
        if (bitmapF != null) {
            return bitmapF;
        }
        if (config == null) {
            config = f;
        }
        return Bitmap.createBitmap(i, i2, config);
    }

    @Override // com.bumptech.glide.load.engine.bitmap_recycle.a
    public final synchronized void b(Bitmap bitmap) {
        try {
            if (bitmap == null) {
                throw new NullPointerException("Bitmap must not be null");
            }
            if (bitmap.isRecycled()) {
                throw new IllegalStateException("Cannot pool recycled bitmap");
            }
            if (bitmap.isMutable()) {
                this.a.getClass();
                if (m.c(bitmap) <= this.d && this.b.contains(bitmap.getConfig())) {
                    this.a.getClass();
                    int iC = m.c(bitmap);
                    this.a.e(bitmap);
                    this.c.getClass();
                    this.e += iC;
                    if (Log.isLoggable("LruBitmapPool", 2)) {
                        this.a.getClass();
                        j.c(m.c(bitmap), bitmap.getConfig());
                    }
                    if (Log.isLoggable("LruBitmapPool", 2)) {
                        Objects.toString(this.a);
                    }
                    g(this.d);
                    return;
                }
            }
            if (Log.isLoggable("LruBitmapPool", 2)) {
                this.a.getClass();
                j.c(m.c(bitmap), bitmap.getConfig());
                bitmap.isMutable();
                this.b.contains(bitmap.getConfig());
            }
            bitmap.recycle();
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // com.bumptech.glide.load.engine.bitmap_recycle.a
    public final Bitmap c(int i, int i2, Bitmap.Config config) {
        Bitmap bitmapF = f(i, i2, config);
        if (bitmapF != null) {
            bitmapF.eraseColor(0);
            return bitmapF;
        }
        if (config == null) {
            config = f;
        }
        return Bitmap.createBitmap(i, i2, config);
    }

    @Override // com.bumptech.glide.load.engine.bitmap_recycle.a
    public final void d(int i) {
        Log.isLoggable("LruBitmapPool", 3);
        if (i >= 40 || i >= 20) {
            e();
        } else if (i >= 20 || i == 15) {
            g(this.d / 2);
        }
    }

    @Override // com.bumptech.glide.load.engine.bitmap_recycle.a
    public final void e() {
        Log.isLoggable("LruBitmapPool", 3);
        g(0L);
    }

    public final synchronized Bitmap f(int i, int i2, Bitmap.Config config) {
        Bitmap bitmapB;
        try {
            if (config == Bitmap.Config.HARDWARE) {
                throw new IllegalArgumentException("Cannot create a mutable Bitmap with config: " + config + ". Consider setting Downsampler#ALLOW_HARDWARE_CONFIG to false in your RequestOptions and/or in GlideBuilder.setDefaultRequestOptions");
            }
            bitmapB = this.a.b(i, i2, config != null ? config : f);
            if (bitmapB != null) {
                long j = this.e;
                this.a.getClass();
                this.e = j - m.c(bitmapB);
                this.c.getClass();
                bitmapB.setHasAlpha(true);
                bitmapB.setPremultiplied(true);
            } else if (Log.isLoggable("LruBitmapPool", 3)) {
                this.a.getClass();
                j.c(m.d(config) * i * i2, config);
            }
            if (Log.isLoggable("LruBitmapPool", 2)) {
                this.a.getClass();
                j.c(m.d(config) * i * i2, config);
            }
            if (Log.isLoggable("LruBitmapPool", 2)) {
                Objects.toString(this.a);
            }
        } catch (Throwable th) {
            throw th;
        }
        return bitmapB;
    }

    public final synchronized void g(long j) {
        while (this.e > j) {
            try {
                j jVar = this.a;
                Bitmap bitmap = (Bitmap) jVar.b.n();
                if (bitmap != null) {
                    jVar.a(Integer.valueOf(m.c(bitmap)), bitmap);
                }
                if (bitmap == null) {
                    if (Log.isLoggable("LruBitmapPool", 5)) {
                        Log.w("LruBitmapPool", "Size mismatch, resetting");
                        Objects.toString(this.a);
                    }
                    this.e = 0L;
                    return;
                }
                this.c.getClass();
                long j2 = this.e;
                this.a.getClass();
                this.e = j2 - m.c(bitmap);
                if (Log.isLoggable("LruBitmapPool", 3)) {
                    this.a.getClass();
                    j.c(m.c(bitmap), bitmap.getConfig());
                }
                if (Log.isLoggable("LruBitmapPool", 2)) {
                    Objects.toString(this.a);
                }
                bitmap.recycle();
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
