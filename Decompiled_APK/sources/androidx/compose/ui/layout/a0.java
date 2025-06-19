package androidx.compose.ui.layout;

import com.google.android.gms.internal.mlkit_vision_barcode.W4;

/* loaded from: classes.dex */
public abstract class a0 {
    public static final long a = AbstractC0897s.b(Float.NaN, Float.NaN);
    public static final /* synthetic */ int b = 0;

    public static final float a(long j) {
        if (j != a) {
            return Float.intBitsToFloat((int) (j >> 32));
        }
        W4.f("ScaleFactor is unspecified");
        throw null;
    }

    public static final float b(long j) {
        if (j != a) {
            return Float.intBitsToFloat((int) (j & 4294967295L));
        }
        W4.f("ScaleFactor is unspecified");
        throw null;
    }
}
