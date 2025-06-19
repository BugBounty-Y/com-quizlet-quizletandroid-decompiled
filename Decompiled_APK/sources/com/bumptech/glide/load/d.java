package com.bumptech.glide.load;

import androidx.compose.foundation.lazy.grid.m;
import java.io.InputStream;
import java.nio.ByteBuffer;

/* loaded from: classes.dex */
public interface d {
    ImageHeaderParser$ImageType a(ByteBuffer byteBuffer);

    int b(InputStream inputStream, m mVar);

    ImageHeaderParser$ImageType c(InputStream inputStream);

    int d(ByteBuffer byteBuffer, m mVar);
}
