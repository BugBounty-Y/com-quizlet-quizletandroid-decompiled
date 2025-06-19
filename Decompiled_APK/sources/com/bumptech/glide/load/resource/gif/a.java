package com.bumptech.glide.load.resource.gif;

import android.content.Context;
import android.graphics.Bitmap;
import android.os.SystemClock;
import android.util.Log;
import androidx.compose.foundation.lazy.grid.m;
import com.bumptech.glide.Glide;
import com.bumptech.glide.load.ImageHeaderParser$ImageType;
import com.bumptech.glide.load.j;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3567z;
import java.nio.ByteBuffer;
import java.util.ArrayList;

/* loaded from: classes.dex */
public class a implements j {
    public static final com.quizlet.shared.usecase.studiableMetadata.a f = new com.quizlet.shared.usecase.studiableMetadata.a(6);
    public static final com.google.android.gms.internal.instantapps.a g = new com.google.android.gms.internal.instantapps.a(21);
    public final Context a;
    public final ArrayList b;
    public final com.google.android.gms.internal.instantapps.a c;
    public final com.quizlet.shared.usecase.studiableMetadata.a d;
    public final androidx.work.impl.model.c e;

    public a(Context context) {
        this(context, Glide.a(context).c.a().e(), Glide.a(context).a, Glide.a(context).d);
    }

    @Override // com.bumptech.glide.load.j
    public final boolean a(Object obj, com.bumptech.glide.load.h hVar) {
        return !((Boolean) hVar.c(h.b)).booleanValue() && AbstractC3567z.c(this.b, (ByteBuffer) obj) == ImageHeaderParser$ImageType.GIF;
    }

    /*  JADX ERROR: JadxRuntimeException in pass: RegionMakerVisitor
        jadx.core.utils.exceptions.JadxRuntimeException: Can't find top splitter block for handler:B:25:0x005b
        	at jadx.core.utils.BlockUtils.getTopSplitterForHandler(BlockUtils.java:1178)
        	at jadx.core.dex.visitors.regions.maker.ExcHandlersRegionMaker.collectHandlerRegions(ExcHandlersRegionMaker.java:53)
        	at jadx.core.dex.visitors.regions.maker.ExcHandlersRegionMaker.process(ExcHandlersRegionMaker.java:38)
        	at jadx.core.dex.visitors.regions.RegionMakerVisitor.visit(RegionMakerVisitor.java:27)
        */
    @Override // com.bumptech.glide.load.j
    public final com.bumptech.glide.load.engine.v b(java.lang.Object r8, int r9, int r10, com.bumptech.glide.load.h r11) {
        /*
            r7 = this;
            r2 = r8
            java.nio.ByteBuffer r2 = (java.nio.ByteBuffer) r2
            com.google.android.gms.internal.instantapps.a r8 = r7.c
            monitor-enter(r8)
            java.lang.Object r0 = r8.b     // Catch: java.lang.Throwable -> L56
            java.util.ArrayDeque r0 = (java.util.ArrayDeque) r0     // Catch: java.lang.Throwable -> L56
            java.lang.Object r0 = r0.poll()     // Catch: java.lang.Throwable -> L56
            com.bumptech.glide.gifdecoder.c r0 = (com.bumptech.glide.gifdecoder.c) r0     // Catch: java.lang.Throwable -> L56
            if (r0 != 0) goto L17
            com.bumptech.glide.gifdecoder.c r0 = new com.bumptech.glide.gifdecoder.c     // Catch: java.lang.Throwable -> L19
            r0.<init>()     // Catch: java.lang.Throwable -> L19
        L17:
            r5 = r0
            goto L1d
        L19:
            r0 = move-exception
            r9 = r0
            r1 = r7
            goto L59
        L1d:
            r0 = 0
            r5.b = r0     // Catch: java.lang.Throwable -> L56
            byte[] r0 = r5.a     // Catch: java.lang.Throwable -> L56
            r1 = 0
            java.util.Arrays.fill(r0, r1)     // Catch: java.lang.Throwable -> L56
            com.bumptech.glide.gifdecoder.b r0 = new com.bumptech.glide.gifdecoder.b     // Catch: java.lang.Throwable -> L56
            r0.<init>()     // Catch: java.lang.Throwable -> L56
            r5.c = r0     // Catch: java.lang.Throwable -> L56
            r5.d = r1     // Catch: java.lang.Throwable -> L56
            java.nio.ByteBuffer r0 = r2.asReadOnlyBuffer()     // Catch: java.lang.Throwable -> L56
            r5.b = r0     // Catch: java.lang.Throwable -> L56
            r0.position(r1)     // Catch: java.lang.Throwable -> L56
            java.nio.ByteBuffer r0 = r5.b     // Catch: java.lang.Throwable -> L56
            java.nio.ByteOrder r1 = java.nio.ByteOrder.LITTLE_ENDIAN     // Catch: java.lang.Throwable -> L56
            r0.order(r1)     // Catch: java.lang.Throwable -> L56
            monitor-exit(r8)
            r1 = r7
            r3 = r9
            r4 = r10
            r6 = r11
            com.bumptech.glide.load.resource.drawable.b r8 = r1.c(r2, r3, r4, r5, r6)     // Catch: java.lang.Throwable -> L4e
            com.google.android.gms.internal.instantapps.a r9 = r1.c
            r9.E(r5)
            return r8
        L4e:
            r0 = move-exception
            r8 = r0
            com.google.android.gms.internal.instantapps.a r9 = r1.c
            r9.E(r5)
            throw r8
        L56:
            r0 = move-exception
            r1 = r7
        L58:
            r9 = r0
        L59:
            monitor-exit(r8)     // Catch: java.lang.Throwable -> L5b
            throw r9
        L5b:
            r0 = move-exception
            goto L58
        */
        throw new UnsupportedOperationException("Method not decompiled: com.bumptech.glide.load.resource.gif.a.b(java.lang.Object, int, int, com.bumptech.glide.load.h):com.bumptech.glide.load.engine.v");
    }

    public final com.bumptech.glide.load.resource.drawable.b c(ByteBuffer byteBuffer, int i, int i2, com.bumptech.glide.gifdecoder.c cVar, com.bumptech.glide.load.h hVar) {
        int i3 = com.bumptech.glide.util.h.a;
        SystemClock.elapsedRealtimeNanos();
        try {
            com.bumptech.glide.gifdecoder.b bVarB = cVar.b();
            if (bVarB.c > 0 && bVarB.b == 0) {
                Bitmap.Config config = hVar.c(h.a) == com.bumptech.glide.load.a.b ? Bitmap.Config.RGB_565 : Bitmap.Config.ARGB_8888;
                int iMin = Math.min(bVarB.g / i2, bVarB.f / i);
                int iMax = Math.max(1, iMin == 0 ? 0 : Integer.highestOneBit(iMin));
                Log.isLoggable("BufferGifDecoder", 2);
                com.quizlet.shared.usecase.studiableMetadata.a aVar = this.d;
                androidx.work.impl.model.c cVar2 = this.e;
                aVar.getClass();
                com.bumptech.glide.gifdecoder.d dVar = new com.bumptech.glide.gifdecoder.d(cVar2, bVarB, byteBuffer, iMax);
                dVar.c(config);
                dVar.k = (dVar.k + 1) % dVar.l.c;
                Bitmap bitmapB = dVar.b();
                if (bitmapB != null) {
                    com.bumptech.glide.load.resource.drawable.b bVar = new com.bumptech.glide.load.resource.drawable.b(new b(new androidx.vectordrawable.graphics.drawable.e(new g(Glide.a(this.a), dVar, i, i2, bitmapB), 1)), 1);
                    if (Log.isLoggable("BufferGifDecoder", 2)) {
                        SystemClock.elapsedRealtimeNanos();
                    }
                    return bVar;
                }
                if (Log.isLoggable("BufferGifDecoder", 2)) {
                    SystemClock.elapsedRealtimeNanos();
                    return null;
                }
            }
            return null;
        } finally {
            if (Log.isLoggable("BufferGifDecoder", 2)) {
                SystemClock.elapsedRealtimeNanos();
            }
        }
    }

    public a(Context context, ArrayList arrayList, com.bumptech.glide.load.engine.bitmap_recycle.a aVar, m mVar) {
        com.quizlet.shared.usecase.studiableMetadata.a aVar2 = f;
        this.a = context.getApplicationContext();
        this.b = arrayList;
        this.d = aVar2;
        this.e = new androidx.work.impl.model.c(8, aVar, mVar);
        this.c = g;
    }
}
