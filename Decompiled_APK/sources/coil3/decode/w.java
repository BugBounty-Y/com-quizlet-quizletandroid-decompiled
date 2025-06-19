package coil3.decode;

import android.graphics.Bitmap;
import android.graphics.ColorSpace;
import android.graphics.ImageDecoder;
import android.graphics.ImageDecoder$OnHeaderDecodedListener;
import android.util.Size;
import com.google.android.gms.internal.mlkit_vision_camera.s3;
import kotlin.jvm.internal.F;

/* loaded from: classes.dex */
public final class w implements ImageDecoder$OnHeaderDecodedListener {
    public final /* synthetic */ x a;
    public final /* synthetic */ F b;

    public w(x xVar, F f) {
        this.a = xVar;
        this.b = f;
    }

    public final void onHeaderDecoded(ImageDecoder imageDecoder, ImageDecoder.ImageInfo imageInfo, ImageDecoder.Source source) {
        Size size = imageInfo.getSize();
        int width = size.getWidth();
        int height = size.getHeight();
        coil3.request.m mVar = this.a.c;
        long jA = s3.a(width, height, mVar.b, mVar.c, (coil3.size.h) coil3.n.e(mVar, coil3.request.h.b));
        int i = (int) (jA >> 32);
        int i2 = (int) (jA & 4294967295L);
        if (width > 0 && height > 0 && (width != i || height != i2)) {
            double dB = s3.b(width, height, i, i2, this.a.c.c);
            F f = this.b;
            boolean z = dB < 1.0d;
            f.a = z;
            if (z || this.a.c.d == coil3.size.d.a) {
                imageDecoder.setTargetSize(kotlin.math.c.a(width * dB), kotlin.math.c.a(dB * height));
            }
        }
        x xVar = this.a;
        imageDecoder.setOnPartialImageListener(new t());
        coil3.request.m mVar2 = xVar.c;
        imageDecoder.setAllocator(coil3.request.i.a(mVar2) == Bitmap.Config.HARDWARE ? 3 : 1);
        imageDecoder.setMemorySizePolicy(!((Boolean) coil3.n.e(mVar2, coil3.request.i.g)).booleanValue() ? 1 : 0);
        androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.e eVar = coil3.request.i.c;
        if (((ColorSpace) coil3.n.e(mVar2, eVar)) != null) {
            imageDecoder.setTargetColorSpace((ColorSpace) coil3.n.e(mVar2, eVar));
        }
        imageDecoder.setUnpremultipliedRequired(!((Boolean) coil3.n.e(mVar2, coil3.request.i.d)).booleanValue());
    }
}
