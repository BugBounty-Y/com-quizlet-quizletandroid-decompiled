package com.bumptech.glide.load.resource.transcode;

/* loaded from: classes.dex */
public final class d implements b {
    public static final d b = new d(0);
    public final /* synthetic */ int a;

    public /* synthetic */ d(int i) {
        this.a = i;
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x0051  */
    @Override // com.bumptech.glide.load.resource.transcode.b
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.bumptech.glide.load.engine.v d(com.bumptech.glide.load.engine.v r6, com.bumptech.glide.load.h r7) {
        /*
            r5 = this;
            int r7 = r5.a
            switch(r7) {
                case 0: goto L6a;
                default: goto L5;
            }
        L5:
            java.lang.Object r6 = r6.get()
            com.bumptech.glide.load.resource.gif.b r6 = (com.bumptech.glide.load.resource.gif.b) r6
            androidx.vectordrawable.graphics.drawable.e r6 = r6.a
            java.lang.Object r6 = r6.b
            com.bumptech.glide.load.resource.gif.g r6 = (com.bumptech.glide.load.resource.gif.g) r6
            com.bumptech.glide.gifdecoder.d r6 = r6.a
            java.nio.ByteBuffer r6 = r6.d
            java.nio.ByteBuffer r6 = r6.asReadOnlyBuffer()
            com.bumptech.glide.load.resource.bitmap.A r7 = new com.bumptech.glide.load.resource.bitmap.A
            java.util.concurrent.atomic.AtomicReference r0 = com.bumptech.glide.util.b.a
            boolean r0 = r6.isReadOnly()
            if (r0 != 0) goto L3c
            boolean r0 = r6.hasArray()
            if (r0 == 0) goto L3c
            androidx.compose.animation.core.U0 r0 = new androidx.compose.animation.core.U0
            byte[] r1 = r6.array()
            int r2 = r6.arrayOffset()
            int r3 = r6.limit()
            r4 = 4
            r0.<init>(r1, r2, r3, r4)
            goto L3d
        L3c:
            r0 = 0
        L3d:
            if (r0 == 0) goto L51
            int r1 = r0.b
            if (r1 != 0) goto L51
            java.lang.Object r1 = r0.d
            byte[] r1 = (byte[]) r1
            int r1 = r1.length
            int r0 = r0.c
            if (r0 != r1) goto L51
            byte[] r6 = r6.array()
            goto L66
        L51:
            java.nio.ByteBuffer r6 = r6.asReadOnlyBuffer()
            int r0 = r6.limit()
            byte[] r0 = new byte[r0]
            r1 = 0
            java.nio.Buffer r1 = r6.position(r1)
            java.nio.ByteBuffer r1 = (java.nio.ByteBuffer) r1
            r6.get(r0)
            r6 = r0
        L66:
            r7.<init>(r6)
            return r7
        L6a:
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.bumptech.glide.load.resource.transcode.d.d(com.bumptech.glide.load.engine.v, com.bumptech.glide.load.h):com.bumptech.glide.load.engine.v");
    }
}
