package androidx.compose.foundation.lazy;

import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.C0253l0;
import androidx.compose.animation.core.V0;
import androidx.compose.foundation.lazy.layout.LazyLayoutAnimateItemElement;
import androidx.compose.runtime.H0;
import com.google.android.gms.internal.mlkit_vision_barcode.P5;

/* renamed from: androidx.compose.foundation.lazy.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0422b {
    public H0 a;
    public H0 b;

    public static androidx.compose.ui.q a(C0422b c0422b, int i) {
        C0253l0 c0253l0Q = (i & 1) != 0 ? AbstractC0240f.q(5, null) : null;
        Object obj = V0.a;
        C0253l0 c0253l0Q2 = AbstractC0240f.q(1, new androidx.compose.ui.unit.h(P5.b(1, 1)));
        C0253l0 c0253l0Q3 = (i & 4) != 0 ? AbstractC0240f.q(5, null) : null;
        c0422b.getClass();
        return new LazyLayoutAnimateItemElement(c0253l0Q, c0253l0Q2, c0253l0Q3);
    }

    public static androidx.compose.ui.q b(C0422b c0422b) {
        return new ParentSizeElement(c0422b.a);
    }
}
