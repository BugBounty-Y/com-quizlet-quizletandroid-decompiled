package com.android.volley.toolbox;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.widget.ImageView;
import com.android.volley.ParseError;
import com.android.volley.k;
import com.android.volley.l;
import com.android.volley.t;
import com.android.volley.y;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3556x;
import com.pubmatic.sdk.common.network.g;

/* loaded from: classes.dex */
public final class f extends l {
    public static final Object j = new Object();
    public final Object d;
    public g.c e;
    public final Bitmap.Config f;
    public final int g;
    public final int h;
    public final ImageView.ScaleType i;

    public f(String str, g.c cVar, int i, int i2, ImageView.ScaleType scaleType, Bitmap.Config config, g.d dVar) {
        super(0, str, dVar);
        this.d = new Object();
        setRetryPolicy(new com.android.volley.d(1000, 2.0f, 2));
        this.e = cVar;
        this.f = config;
        this.g = i;
        this.h = i2;
        this.i = scaleType;
    }

    public static int c(int i, int i2, int i3, int i4, ImageView.ScaleType scaleType) {
        if (i != 0 || i2 != 0) {
            if (scaleType != ImageView.ScaleType.FIT_XY) {
                if (i == 0) {
                    return (int) (i3 * (i2 / i4));
                }
                if (i2 == 0) {
                    return i;
                }
                double d = i4 / i3;
                if (scaleType == ImageView.ScaleType.CENTER_CROP) {
                    double d2 = i2;
                    return ((double) i) * d < d2 ? (int) (d2 / d) : i;
                }
                double d3 = i2;
                return ((double) i) * d > d3 ? (int) (d3 / d) : i;
            }
            if (i != 0) {
                return i;
            }
        }
        return i3;
    }

    public final t b(com.android.volley.h hVar) {
        Bitmap bitmapDecodeByteArray;
        BitmapFactory.Options options = new BitmapFactory.Options();
        byte[] bArr = hVar.b;
        int i = this.h;
        int i2 = this.g;
        if (i2 == 0 && i == 0) {
            options.inPreferredConfig = this.f;
            bitmapDecodeByteArray = BitmapFactory.decodeByteArray(bArr, 0, bArr.length, options);
        } else {
            options.inJustDecodeBounds = true;
            BitmapFactory.decodeByteArray(bArr, 0, bArr.length, options);
            int i3 = options.outWidth;
            int i4 = options.outHeight;
            ImageView.ScaleType scaleType = this.i;
            int iC = c(i2, i, i3, i4, scaleType);
            int iC2 = c(i, i2, i4, i3, scaleType);
            options.inJustDecodeBounds = false;
            float f = 1.0f;
            while (true) {
                float f2 = 2.0f * f;
                if (f2 > Math.min(i3 / iC, i4 / iC2)) {
                    break;
                }
                f = f2;
            }
            options.inSampleSize = (int) f;
            bitmapDecodeByteArray = BitmapFactory.decodeByteArray(bArr, 0, bArr.length, options);
            if (bitmapDecodeByteArray != null && (bitmapDecodeByteArray.getWidth() > iC || bitmapDecodeByteArray.getHeight() > iC2)) {
                Bitmap bitmapCreateScaledBitmap = Bitmap.createScaledBitmap(bitmapDecodeByteArray, iC, iC2, true);
                bitmapDecodeByteArray.recycle();
                bitmapDecodeByteArray = bitmapCreateScaledBitmap;
            }
        }
        return bitmapDecodeByteArray == null ? new t(new ParseError(hVar)) : new t(bitmapDecodeByteArray, AbstractC3556x.a(hVar));
    }

    @Override // com.android.volley.l
    public final void cancel() {
        super.cancel();
        synchronized (this.d) {
            this.e = null;
        }
    }

    @Override // com.android.volley.l
    public final void deliverResponse(Object obj) {
        g.c cVar;
        Bitmap bitmap = (Bitmap) obj;
        synchronized (this.d) {
            cVar = this.e;
        }
        if (cVar != null) {
            cVar.onResponse(bitmap);
        }
    }

    @Override // com.android.volley.l
    public final k getPriority() {
        return k.a;
    }

    @Override // com.android.volley.l
    public final t parseNetworkResponse(com.android.volley.h hVar) {
        t tVarB;
        synchronized (j) {
            try {
                try {
                    tVarB = b(hVar);
                } catch (OutOfMemoryError e) {
                    y.b("Caught OOM for %d byte image, url=%s", Integer.valueOf(hVar.b.length), getUrl());
                    return new t(new ParseError(e));
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return tVarB;
    }
}
