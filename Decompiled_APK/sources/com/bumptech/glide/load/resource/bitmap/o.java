package com.bumptech.glide.load.resource.bitmap;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.util.DisplayMetrics;
import com.bumptech.glide.load.ImageHeaderParser$ImageType;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;

/* loaded from: classes.dex */
public final class o {
    public static final com.bumptech.glide.load.g f = com.bumptech.glide.load.g.a(com.bumptech.glide.load.a.c, "com.bumptech.glide.load.resource.bitmap.Downsampler.DecodeFormat");
    public static final com.bumptech.glide.load.g g = new com.bumptech.glide.load.g("com.bumptech.glide.load.resource.bitmap.Downsampler.PreferredColorSpace", null, com.bumptech.glide.load.g.e);
    public static final com.bumptech.glide.load.g h;
    public static final com.bumptech.glide.load.g i;
    public static final com.quizlet.shared.usecase.folderstudymaterials.a j;
    public static final ArrayDeque k;
    public final com.bumptech.glide.load.engine.bitmap_recycle.a a;
    public final DisplayMetrics b;
    public final androidx.compose.foundation.lazy.grid.m c;
    public final ArrayList d;
    public final u e = u.a();

    static {
        m mVar = m.b;
        Boolean bool = Boolean.FALSE;
        h = com.bumptech.glide.load.g.a(bool, "com.bumptech.glide.load.resource.bitmap.Downsampler.FixBitmapSize");
        i = com.bumptech.glide.load.g.a(bool, "com.bumptech.glide.load.resource.bitmap.Downsampler.AllowHardwareDecode");
        Collections.unmodifiableSet(new HashSet(Arrays.asList("image/vnd.wap.wbmp", "image/x-ico")));
        j = new com.quizlet.shared.usecase.folderstudymaterials.a(6);
        Collections.unmodifiableSet(EnumSet.of(ImageHeaderParser$ImageType.JPEG, ImageHeaderParser$ImageType.PNG_A, ImageHeaderParser$ImageType.PNG));
        char[] cArr = com.bumptech.glide.util.m.a;
        k = new ArrayDeque(0);
    }

    public o(ArrayList arrayList, DisplayMetrics displayMetrics, com.bumptech.glide.load.engine.bitmap_recycle.a aVar, androidx.compose.foundation.lazy.grid.m mVar) {
        this.d = arrayList;
        com.bumptech.glide.util.f.c(displayMetrics, "Argument must not be null");
        this.b = displayMetrics;
        com.bumptech.glide.util.f.c(aVar, "Argument must not be null");
        this.a = aVar;
        com.bumptech.glide.util.f.c(mVar, "Argument must not be null");
        this.c = mVar;
    }

    /* JADX WARN: Code restructure failed: missing block: B:24:?, code lost:
    
        throw r4;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static android.graphics.Bitmap c(com.bumptech.glide.load.resource.bitmap.v r8, android.graphics.BitmapFactory.Options r9, com.bumptech.glide.load.resource.bitmap.n r10, com.bumptech.glide.load.engine.bitmap_recycle.a r11) {
        /*
            boolean r0 = r9.inJustDecodeBounds
            if (r0 != 0) goto La
            r10.i()
            r8.e()
        La:
            int r0 = r9.outWidth
            int r1 = r9.outHeight
            java.lang.String r2 = r9.outMimeType
            java.util.concurrent.locks.Lock r3 = com.bumptech.glide.load.resource.bitmap.z.d
            r3.lock()
            android.graphics.Bitmap r8 = r8.d(r9)     // Catch: java.lang.IllegalArgumentException -> L1d java.lang.Throwable -> L5e
            r3.unlock()
            return r8
        L1d:
            r3 = move-exception
            java.io.IOException r4 = new java.io.IOException     // Catch: java.lang.Throwable -> L5e
            java.lang.String r5 = "Exception decoding bitmap, outWidth: "
            java.lang.String r6 = ", outHeight: "
            java.lang.String r7 = ", outMimeType: "
            java.lang.StringBuilder r0 = android.support.v4.media.session.a.w(r5, r0, r6, r7, r1)     // Catch: java.lang.Throwable -> L5e
            r0.append(r2)     // Catch: java.lang.Throwable -> L5e
            java.lang.String r1 = ", inBitmap: "
            r0.append(r1)     // Catch: java.lang.Throwable -> L5e
            android.graphics.Bitmap r1 = r9.inBitmap     // Catch: java.lang.Throwable -> L5e
            java.lang.String r1 = d(r1)     // Catch: java.lang.Throwable -> L5e
            r0.append(r1)     // Catch: java.lang.Throwable -> L5e
            java.lang.String r0 = r0.toString()     // Catch: java.lang.Throwable -> L5e
            r4.<init>(r0, r3)     // Catch: java.lang.Throwable -> L5e
            java.lang.String r0 = "Downsampler"
            r1 = 3
            android.util.Log.isLoggable(r0, r1)     // Catch: java.lang.Throwable -> L5e
            android.graphics.Bitmap r0 = r9.inBitmap     // Catch: java.lang.Throwable -> L5e
            if (r0 == 0) goto L5d
            r11.b(r0)     // Catch: java.io.IOException -> L5c java.lang.Throwable -> L5e
            r0 = 0
            r9.inBitmap = r0     // Catch: java.io.IOException -> L5c java.lang.Throwable -> L5e
            android.graphics.Bitmap r8 = c(r8, r9, r10, r11)     // Catch: java.io.IOException -> L5c java.lang.Throwable -> L5e
            java.util.concurrent.locks.Lock r9 = com.bumptech.glide.load.resource.bitmap.z.d
            r9.unlock()
            return r8
        L5c:
            throw r4     // Catch: java.lang.Throwable -> L5e
        L5d:
            throw r4     // Catch: java.lang.Throwable -> L5e
        L5e:
            r8 = move-exception
            java.util.concurrent.locks.Lock r9 = com.bumptech.glide.load.resource.bitmap.z.d
            r9.unlock()
            throw r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.bumptech.glide.load.resource.bitmap.o.c(com.bumptech.glide.load.resource.bitmap.v, android.graphics.BitmapFactory$Options, com.bumptech.glide.load.resource.bitmap.n, com.bumptech.glide.load.engine.bitmap_recycle.a):android.graphics.Bitmap");
    }

    public static String d(Bitmap bitmap) {
        if (bitmap == null) {
            return null;
        }
        return "[" + bitmap.getWidth() + "x" + bitmap.getHeight() + "] " + bitmap.getConfig() + (" (" + bitmap.getAllocationByteCount() + ")");
    }

    public static void e(BitmapFactory.Options options) {
        options.inTempStorage = null;
        options.inDither = false;
        options.inScaled = false;
        options.inSampleSize = 1;
        options.inPreferredConfig = null;
        options.inJustDecodeBounds = false;
        options.inDensity = 0;
        options.inTargetDensity = 0;
        options.inPreferredColorSpace = null;
        options.outColorSpace = null;
        options.outConfig = null;
        options.outWidth = 0;
        options.outHeight = 0;
        options.outMimeType = null;
        options.inBitmap = null;
        options.inMutable = true;
    }

    public final C1541d a(v vVar, int i2, int i3, com.bumptech.glide.load.h hVar, n nVar) {
        ArrayDeque arrayDeque;
        BitmapFactory.Options options;
        byte[] bArr = (byte[]) this.c.f(65536, byte[].class);
        synchronized (o.class) {
            arrayDeque = k;
            synchronized (arrayDeque) {
                options = (BitmapFactory.Options) arrayDeque.poll();
            }
            if (options == null) {
                options = new BitmapFactory.Options();
                e(options);
            }
        }
        options.inTempStorage = bArr;
        com.bumptech.glide.load.a aVar = (com.bumptech.glide.load.a) hVar.c(f);
        com.bumptech.glide.load.i iVar = (com.bumptech.glide.load.i) hVar.c(g);
        m mVar = (m) hVar.c(m.g);
        boolean zBooleanValue = ((Boolean) hVar.c(h)).booleanValue();
        com.bumptech.glide.load.g gVar = i;
        try {
            C1541d c1541dD = C1541d.d(b(vVar, options, mVar, aVar, iVar, hVar.c(gVar) != null && ((Boolean) hVar.c(gVar)).booleanValue(), i2, i3, zBooleanValue, nVar), this.a);
            e(options);
            synchronized (arrayDeque) {
                arrayDeque.offer(options);
            }
            this.c.k(bArr);
            return c1541dD;
        } catch (Throwable th) {
            e(options);
            ArrayDeque arrayDeque2 = k;
            synchronized (arrayDeque2) {
                arrayDeque2.offer(options);
                this.c.k(bArr);
                throw th;
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:106:0x021d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.graphics.Bitmap b(com.bumptech.glide.load.resource.bitmap.v r29, android.graphics.BitmapFactory.Options r30, com.bumptech.glide.load.resource.bitmap.m r31, com.bumptech.glide.load.a r32, com.bumptech.glide.load.i r33, boolean r34, int r35, int r36, boolean r37, com.bumptech.glide.load.resource.bitmap.n r38) {
        /*
            Method dump skipped, instructions count: 992
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.bumptech.glide.load.resource.bitmap.o.b(com.bumptech.glide.load.resource.bitmap.v, android.graphics.BitmapFactory$Options, com.bumptech.glide.load.resource.bitmap.m, com.bumptech.glide.load.a, com.bumptech.glide.load.i, boolean, int, int, boolean, com.bumptech.glide.load.resource.bitmap.n):android.graphics.Bitmap");
    }
}
