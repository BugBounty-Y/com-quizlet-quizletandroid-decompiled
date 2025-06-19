package androidx.camera.core;

import android.graphics.Bitmap;
import android.media.Image;
import android.media.ImageWriter;
import android.util.Log;
import android.view.Surface;
import androidx.annotation.NonNull;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import java.nio.ByteBuffer;
import java.util.Locale;

/* loaded from: classes.dex */
public abstract class ImageProcessingUtil {
    public static int a;

    static {
        System.loadLibrary("image_processing_util_jni");
    }

    public static void a(O o) {
        if (!d(o)) {
            AbstractC3053s1.c("ImageProcessingUtil", "Unsupported format for YUV to RGB");
            return;
        }
        int width = o.getWidth();
        int iB = o.b();
        int iQ = o.o()[0].q();
        int iQ2 = o.o()[1].q();
        int iQ3 = o.o()[2].q();
        int iP = o.o()[0].p();
        int iP2 = o.o()[1].p();
        if (nativeShiftPixel(o.o()[0].o(), iQ, o.o()[1].o(), iQ2, o.o()[2].o(), iQ3, iP, iP2, width, iB, iP, iP2, iP2) != 0) {
            AbstractC3053s1.c("ImageProcessingUtil", "One pixel shift for YUV failure");
        }
    }

    public static G b(O o, androidx.camera.core.impl.S s, ByteBuffer byteBuffer, int i, boolean z) {
        if (!d(o)) {
            AbstractC3053s1.c("ImageProcessingUtil", "Unsupported format for YUV to RGB");
            return null;
        }
        System.currentTimeMillis();
        if (i != 0 && i != 90 && i != 180 && i != 270) {
            AbstractC3053s1.c("ImageProcessingUtil", "Unsupported rotation degrees for rotate RGB");
            return null;
        }
        Surface surfaceW = s.w();
        int width = o.getWidth();
        int iB = o.b();
        int iQ = o.o()[0].q();
        int iQ2 = o.o()[1].q();
        int iQ3 = o.o()[2].q();
        int iP = o.o()[0].p();
        int iP2 = o.o()[1].p();
        if (nativeConvertAndroid420ToABGR(o.o()[0].o(), iQ, o.o()[1].o(), iQ2, o.o()[2].o(), iQ3, iP, iP2, surfaceW, byteBuffer, width, iB, z ? iP : 0, z ? iP2 : 0, z ? iP2 : 0, i) != 0) {
            AbstractC3053s1.c("ImageProcessingUtil", "YUV to RGB conversion failure");
            return null;
        }
        if (Log.isLoggable("MH", 3)) {
            Locale locale = Locale.US;
            System.currentTimeMillis();
            AbstractC3053s1.f(3, "ImageProcessingUtil");
            a++;
        }
        O oL = s.l();
        if (oL == null) {
            AbstractC3053s1.c("ImageProcessingUtil", "YUV to RGB acquireLatestImage failure");
            return null;
        }
        G g = new G(oL);
        g.a(new N(oL, o, 1));
        return g;
    }

    public static void c(Bitmap bitmap, ByteBuffer byteBuffer, int i) {
        nativeCopyBetweenByteBufferAndBitmap(bitmap, byteBuffer, i, bitmap.getRowBytes(), bitmap.getWidth(), bitmap.getHeight(), true);
    }

    public static boolean d(O o) {
        return o.m() == 35 && o.o().length == 3;
    }

    public static G e(O o, androidx.camera.core.impl.S s, ImageWriter imageWriter, ByteBuffer byteBuffer, ByteBuffer byteBuffer2, ByteBuffer byteBuffer3, int i) {
        String str;
        if (!d(o)) {
            AbstractC3053s1.c("ImageProcessingUtil", "Unsupported format for rotate YUV");
            return null;
        }
        if (i != 0 && i != 90 && i != 180 && i != 270) {
            AbstractC3053s1.c("ImageProcessingUtil", "Unsupported rotation degrees for rotate YUV");
            return null;
        }
        if (i > 0) {
            int width = o.getWidth();
            int iB = o.b();
            int iQ = o.o()[0].q();
            int iQ2 = o.o()[1].q();
            int iQ3 = o.o()[2].q();
            int iP = o.o()[1].p();
            Image imageDequeueInputImage = imageWriter.dequeueInputImage();
            if (imageDequeueInputImage != null && nativeRotateYUV(o.o()[0].o(), iQ, o.o()[1].o(), iQ2, o.o()[2].o(), iQ3, iP, imageDequeueInputImage.getPlanes()[0].getBuffer(), imageDequeueInputImage.getPlanes()[0].getRowStride(), imageDequeueInputImage.getPlanes()[0].getPixelStride(), imageDequeueInputImage.getPlanes()[1].getBuffer(), imageDequeueInputImage.getPlanes()[1].getRowStride(), imageDequeueInputImage.getPlanes()[1].getPixelStride(), imageDequeueInputImage.getPlanes()[2].getBuffer(), imageDequeueInputImage.getPlanes()[2].getRowStride(), imageDequeueInputImage.getPlanes()[2].getPixelStride(), byteBuffer, byteBuffer2, byteBuffer3, width, iB, i) == 0) {
                imageWriter.queueInputImage(imageDequeueInputImage);
                O oL = s.l();
                if (oL == null) {
                    AbstractC3053s1.c("ImageProcessingUtil", "YUV rotation acquireLatestImage failure");
                    return null;
                }
                G g = new G(oL);
                g.a(new N(oL, o, 0));
                return g;
            }
            str = "ImageProcessingUtil";
        } else {
            str = "ImageProcessingUtil";
        }
        AbstractC3053s1.c(str, "rotate YUV failure");
        return null;
    }

    public static void f(byte[] bArr, Surface surface) {
        surface.getClass();
        if (nativeWriteJpegToSurface(bArr, surface) != 0) {
            AbstractC3053s1.c("ImageProcessingUtil", "Failed to enqueue JPEG image.");
        }
    }

    private static native int nativeConvertAndroid420ToABGR(@NonNull ByteBuffer byteBuffer, int i, @NonNull ByteBuffer byteBuffer2, int i2, @NonNull ByteBuffer byteBuffer3, int i3, int i4, int i5, Surface surface, ByteBuffer byteBuffer4, int i6, int i7, int i8, int i9, int i10, int i11);

    private static native int nativeCopyBetweenByteBufferAndBitmap(Bitmap bitmap, ByteBuffer byteBuffer, int i, int i2, int i3, int i4, boolean z);

    private static native int nativeRotateYUV(@NonNull ByteBuffer byteBuffer, int i, @NonNull ByteBuffer byteBuffer2, int i2, @NonNull ByteBuffer byteBuffer3, int i3, int i4, @NonNull ByteBuffer byteBuffer4, int i5, int i6, @NonNull ByteBuffer byteBuffer5, int i7, int i8, @NonNull ByteBuffer byteBuffer6, int i9, int i10, @NonNull ByteBuffer byteBuffer7, @NonNull ByteBuffer byteBuffer8, @NonNull ByteBuffer byteBuffer9, int i11, int i12, int i13);

    private static native int nativeShiftPixel(@NonNull ByteBuffer byteBuffer, int i, @NonNull ByteBuffer byteBuffer2, int i2, @NonNull ByteBuffer byteBuffer3, int i3, int i4, int i5, int i6, int i7, int i8, int i9, int i10);

    private static native int nativeWriteJpegToSurface(@NonNull byte[] bArr, @NonNull Surface surface);
}
