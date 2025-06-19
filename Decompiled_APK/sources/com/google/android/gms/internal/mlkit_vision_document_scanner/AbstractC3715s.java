package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.graphics.Bitmap;
import android.media.Image;
import com.comscore.streaming.ContentType;
import com.google.mlkit.common.MlKitException;
import java.nio.ByteBuffer;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.s, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3715s {
    public static final /* synthetic */ int a = 0;

    public static ByteBuffer a(com.google.mlkit.vision.common.a aVar) throws MlKitException {
        int i = aVar.f;
        int i2 = 0;
        if (i != -1) {
            if (i == 17) {
                com.google.android.gms.common.internal.u.h(null);
                throw null;
            }
            if (i != 35) {
                if (i != 842094169) {
                    throw new MlKitException("Unsupported image format", 13);
                }
                com.google.android.gms.common.internal.u.h(null);
                throw null;
            }
            Image.Plane[] planeArrA = aVar.a();
            com.google.android.gms.common.internal.u.h(planeArrA);
            int i3 = aVar.c;
            int i4 = aVar.d;
            int i5 = i3 * i4;
            int i6 = i5 / 4;
            byte[] bArr = new byte[i6 + i6 + i5];
            ByteBuffer buffer = planeArrA[1].getBuffer();
            ByteBuffer buffer2 = planeArrA[2].getBuffer();
            int iPosition = buffer2.position();
            int iLimit = buffer.limit();
            buffer2.position(iPosition + 1);
            buffer.limit(iLimit - 1);
            int i7 = (i5 + i5) / 4;
            boolean z = buffer2.remaining() == i7 + (-2) && buffer2.compareTo(buffer) == 0;
            buffer2.position(iPosition);
            buffer.limit(iLimit);
            if (z) {
                planeArrA[0].getBuffer().get(bArr, 0, i5);
                ByteBuffer buffer3 = planeArrA[1].getBuffer();
                planeArrA[2].getBuffer().get(bArr, i5, 1);
                buffer3.get(bArr, i5 + 1, i7 - 1);
            } else {
                b(planeArrA[0], i3, i4, bArr, 0, 1);
                b(planeArrA[1], i3, i4, bArr, i5 + 1, 2);
                b(planeArrA[2], i3, i4, bArr, i5, 2);
            }
            return ByteBuffer.wrap(bArr);
        }
        Bitmap bitmapCopy = aVar.a;
        com.google.android.gms.common.internal.u.h(bitmapCopy);
        if (bitmapCopy.getConfig() == Bitmap.Config.HARDWARE) {
            bitmapCopy = bitmapCopy.copy(Bitmap.Config.ARGB_8888, bitmapCopy.isMutable());
        }
        Bitmap bitmap = bitmapCopy;
        int width = bitmap.getWidth();
        int height = bitmap.getHeight();
        int i8 = width * height;
        int[] iArr = new int[i8];
        bitmap.getPixels(iArr, 0, width, 0, 0, width, height);
        int iCeil = (int) Math.ceil(height / 2.0d);
        ByteBuffer byteBufferAllocateDirect = ByteBuffer.allocateDirect(((iCeil + iCeil) * ((int) Math.ceil(width / 2.0d))) + i8);
        int i9 = 0;
        int i10 = 0;
        int i11 = 0;
        while (i9 < height) {
            int i12 = i2;
            while (i12 < width) {
                int i13 = iArr[i11];
                int i14 = i13 >> 16;
                int i15 = i13 >> 8;
                int i16 = i13 & 255;
                int i17 = i10 + 1;
                int i18 = i14 & 255;
                int i19 = i15 & 255;
                byteBufferAllocateDirect.put(i10, (byte) Math.min(255, ((((i16 * 25) + ((i19 * 129) + (i18 * 66))) + 128) >> 8) + 16));
                if (i9 % 2 == 0 && i11 % 2 == 0) {
                    int i20 = ((((i18 * ContentType.LONG_FORM_ON_DEMAND) - (i19 * 94)) - (i16 * 18)) + 128) >> 8;
                    int i21 = (((((i18 * (-38)) - (i19 * 74)) + (i16 * ContentType.LONG_FORM_ON_DEMAND)) + 128) >> 8) + 128;
                    int i22 = i8 + 1;
                    byteBufferAllocateDirect.put(i8, (byte) Math.min(255, i20 + 128));
                    i8 += 2;
                    byteBufferAllocateDirect.put(i22, (byte) Math.min(255, i21));
                }
                i11++;
                i12++;
                i10 = i17;
            }
            i9++;
            i2 = 0;
        }
        return byteBufferAllocateDirect;
    }

    public static final void b(Image.Plane plane, int i, int i2, byte[] bArr, int i3, int i4) {
        ByteBuffer buffer = plane.getBuffer();
        buffer.rewind();
        int rowStride = ((plane.getRowStride() + buffer.limit()) - 1) / plane.getRowStride();
        if (rowStride == 0) {
            return;
        }
        int i5 = i / (i2 / rowStride);
        int rowStride2 = 0;
        for (int i6 = 0; i6 < rowStride; i6++) {
            int pixelStride = rowStride2;
            for (int i7 = 0; i7 < i5; i7++) {
                bArr[i3] = buffer.get(pixelStride);
                i3 += i4;
                pixelStride += plane.getPixelStride();
            }
            rowStride2 += plane.getRowStride();
        }
    }
}
