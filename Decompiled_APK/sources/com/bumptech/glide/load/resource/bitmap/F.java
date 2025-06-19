package com.bumptech.glide.load.resource.bitmap;

import android.graphics.Bitmap;
import android.media.MediaMetadataRetriever;
import android.os.Build;
import androidx.compose.animation.d0;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;

/* loaded from: classes.dex */
public final class F implements com.bumptech.glide.load.j {
    public static final com.bumptech.glide.load.g d = new com.bumptech.glide.load.g("com.bumptech.glide.load.resource.bitmap.VideoBitmapDecode.TargetFrame", -1L, new com.airbnb.lottie.network.c(16));
    public static final com.bumptech.glide.load.g e = new com.bumptech.glide.load.g("com.bumptech.glide.load.resource.bitmap.VideoBitmapDecode.FrameOption", 2, new com.airbnb.lottie.network.d(20));
    public static final com.quizlet.shared.usecase.folderstudymaterials.d f = new com.quizlet.shared.usecase.folderstudymaterials.d(6);
    public static final List g = Collections.unmodifiableList(Arrays.asList("TP1A", "TD1A.220804.031"));
    public final E a;
    public final com.bumptech.glide.load.engine.bitmap_recycle.a b;
    public final com.quizlet.shared.usecase.folderstudymaterials.d c = f;

    public F(com.bumptech.glide.load.engine.bitmap_recycle.a aVar, E e2) {
        this.b = aVar;
        this.a = e2;
    }

    @Override // com.bumptech.glide.load.j
    public final boolean a(Object obj, com.bumptech.glide.load.h hVar) {
        return true;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.bumptech.glide.load.j
    public final com.bumptech.glide.load.engine.v b(Object obj, int i, int i2, com.bumptech.glide.load.h hVar) throws Exception {
        boolean zIsTerminated;
        boolean zIsTerminated2;
        long jLongValue = ((Long) hVar.c(d)).longValue();
        if (jLongValue < 0 && jLongValue != -1) {
            throw new IllegalArgumentException(d0.n(jLongValue, "Requested frame must be non-negative, or DEFAULT_FRAME, given: "));
        }
        Integer num = (Integer) hVar.c(e);
        if (num == null) {
            num = 2;
        }
        m mVar = (m) hVar.c(m.g);
        if (mVar == null) {
            mVar = m.f;
        }
        m mVar2 = mVar;
        this.c.getClass();
        MediaMetadataRetriever mediaMetadataRetriever = new MediaMetadataRetriever();
        boolean z = false;
        try {
            this.a.m(mediaMetadataRetriever, obj);
            Bitmap bitmapC = c(obj, mediaMetadataRetriever, jLongValue, num.intValue(), i, i2, mVar2);
            if (Build.VERSION.SDK_INT < 29) {
                mediaMetadataRetriever.release();
            } else if (mediaMetadataRetriever instanceof AutoCloseable) {
                mediaMetadataRetriever.close();
            } else if (mediaMetadataRetriever instanceof ExecutorService) {
                ExecutorService executorService = (ExecutorService) mediaMetadataRetriever;
                if (executorService != ForkJoinPool.commonPool() && !(zIsTerminated2 = executorService.isTerminated())) {
                    executorService.shutdown();
                    while (!zIsTerminated2) {
                        try {
                            zIsTerminated2 = executorService.awaitTermination(1L, TimeUnit.DAYS);
                        } catch (InterruptedException unused) {
                            if (!z) {
                                executorService.shutdownNow();
                                z = true;
                            }
                        }
                    }
                    if (z) {
                        Thread.currentThread().interrupt();
                    }
                }
            } else {
                mediaMetadataRetriever.release();
            }
            return C1541d.d(bitmapC, this.b);
        } catch (Throwable th) {
            if (Build.VERSION.SDK_INT < 29) {
                mediaMetadataRetriever.release();
            } else if (mediaMetadataRetriever instanceof AutoCloseable) {
                mediaMetadataRetriever.close();
            } else if (mediaMetadataRetriever instanceof ExecutorService) {
                ExecutorService executorService2 = (ExecutorService) mediaMetadataRetriever;
                if (executorService2 != ForkJoinPool.commonPool() && !(zIsTerminated = executorService2.isTerminated())) {
                    executorService2.shutdown();
                    while (!zIsTerminated) {
                        try {
                            zIsTerminated = executorService2.awaitTermination(1L, TimeUnit.DAYS);
                        } catch (InterruptedException unused2) {
                            if (!z) {
                                executorService2.shutdownNow();
                                z = true;
                            }
                        }
                    }
                    if (z) {
                        Thread.currentThread().interrupt();
                    }
                }
            } else {
                mediaMetadataRetriever.release();
            }
            throw th;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:39:0x009f  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00c0  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x00ef  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x010f A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:62:0x0111 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:66:0x0123  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x015f A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:70:0x0160  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.graphics.Bitmap c(java.lang.Object r14, android.media.MediaMetadataRetriever r15, long r16, int r18, int r19, int r20, com.bumptech.glide.load.resource.bitmap.m r21) throws java.lang.NumberFormatException {
        /*
            Method dump skipped, instructions count: 361
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.bumptech.glide.load.resource.bitmap.F.c(java.lang.Object, android.media.MediaMetadataRetriever, long, int, int, int, com.bumptech.glide.load.resource.bitmap.m):android.graphics.Bitmap");
    }
}
