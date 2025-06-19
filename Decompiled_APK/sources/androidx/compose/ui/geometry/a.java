package androidx.compose.ui.geometry;

import com.google.android.gms.internal.mlkit_vision_barcode.O4;
import com.google.android.gms.internal.mlkit_vision_barcode.P4;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public abstract class a {
    public static final long a = O4.a(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE);
    public static final /* synthetic */ int b = 0;

    public static final boolean a(long j, long j2) {
        return j == j2;
    }

    public static final float b(long j) {
        return Float.intBitsToFloat((int) (j >> 32));
    }

    public static final float c(long j) {
        return Float.intBitsToFloat((int) (j & 4294967295L));
    }

    public static String d(long j) {
        if (b(j) == c(j)) {
            return "CornerRadius.circular(" + P4.e(b(j)) + ')';
        }
        return "CornerRadius.elliptical(" + P4.e(b(j)) + ", " + P4.e(c(j)) + ')';
    }
}
