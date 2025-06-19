package com.bumptech.glide.load.resource.bitmap;

import com.bumptech.glide.load.ImageHeaderParser$ImageType;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes.dex */
public final class s implements com.bumptech.glide.load.d {
    @Override // com.bumptech.glide.load.d
    public final ImageHeaderParser$ImageType a(ByteBuffer byteBuffer) {
        return ImageHeaderParser$ImageType.UNKNOWN;
    }

    @Override // com.bumptech.glide.load.d
    public final int b(InputStream inputStream, androidx.compose.foundation.lazy.grid.m mVar) {
        int iC = new androidx.exifinterface.media.h(inputStream).c(1, "Orientation");
        if (iC == 0) {
            return -1;
        }
        return iC;
    }

    @Override // com.bumptech.glide.load.d
    public final ImageHeaderParser$ImageType c(InputStream inputStream) {
        return ImageHeaderParser$ImageType.UNKNOWN;
    }

    @Override // com.bumptech.glide.load.d
    public final int d(ByteBuffer byteBuffer, androidx.compose.foundation.lazy.grid.m mVar) {
        AtomicReference atomicReference = com.bumptech.glide.util.b.a;
        return b(new com.bumptech.glide.util.a(byteBuffer), mVar);
    }
}
