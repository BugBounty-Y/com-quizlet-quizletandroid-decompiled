package androidx.compose.ui.platform;

import com.google.android.gms.internal.mlkit_vision_barcode.N5;

/* loaded from: classes.dex */
public interface Y0 {
    long a();

    long b();

    default float c() {
        return 2.0f;
    }

    default long d() {
        float f = 48;
        return N5.c(f, f);
    }

    default float e() {
        return Float.MAX_VALUE;
    }

    float f();

    default float g() {
        return 16.0f;
    }
}
