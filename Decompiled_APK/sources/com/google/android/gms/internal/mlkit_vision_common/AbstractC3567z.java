package com.google.android.gms.internal.mlkit_vision_common;

import com.bumptech.glide.load.ImageHeaderParser$ImageType;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicReference;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.z, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3567z {
    public static int a(ArrayList arrayList, InputStream inputStream, androidx.compose.foundation.lazy.grid.m mVar) throws IOException {
        if (inputStream != null) {
            if (!inputStream.markSupported()) {
                inputStream = new com.bumptech.glide.load.resource.bitmap.w(inputStream, mVar);
            }
            inputStream.mark(5242880);
            int size = arrayList.size();
            for (int i = 0; i < size; i++) {
                try {
                    int iB = ((com.bumptech.glide.load.d) arrayList.get(i)).b(inputStream, mVar);
                    if (iB != -1) {
                        return iB;
                    }
                } finally {
                    inputStream.reset();
                }
            }
        }
        return -1;
    }

    public static ImageHeaderParser$ImageType b(ArrayList arrayList, InputStream inputStream, androidx.compose.foundation.lazy.grid.m mVar) throws IOException {
        if (inputStream == null) {
            return ImageHeaderParser$ImageType.UNKNOWN;
        }
        if (!inputStream.markSupported()) {
            inputStream = new com.bumptech.glide.load.resource.bitmap.w(inputStream, mVar);
        }
        inputStream.mark(5242880);
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            try {
                ImageHeaderParser$ImageType imageHeaderParser$ImageTypeC = ((com.bumptech.glide.load.d) arrayList.get(i)).c(inputStream);
                inputStream.reset();
                if (imageHeaderParser$ImageTypeC != ImageHeaderParser$ImageType.UNKNOWN) {
                    return imageHeaderParser$ImageTypeC;
                }
            } catch (Throwable th) {
                inputStream.reset();
                throw th;
            }
        }
        return ImageHeaderParser$ImageType.UNKNOWN;
    }

    public static ImageHeaderParser$ImageType c(ArrayList arrayList, ByteBuffer byteBuffer) {
        if (byteBuffer == null) {
            return ImageHeaderParser$ImageType.UNKNOWN;
        }
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            try {
                ImageHeaderParser$ImageType imageHeaderParser$ImageTypeA = ((com.bumptech.glide.load.d) arrayList.get(i)).a(byteBuffer);
                AtomicReference atomicReference = com.bumptech.glide.util.b.a;
                if (imageHeaderParser$ImageTypeA != ImageHeaderParser$ImageType.UNKNOWN) {
                    return imageHeaderParser$ImageTypeA;
                }
            } catch (Throwable th) {
                AtomicReference atomicReference2 = com.bumptech.glide.util.b.a;
                throw th;
            }
        }
        return ImageHeaderParser$ImageType.UNKNOWN;
    }
}
