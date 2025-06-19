package androidx.compose.foundation;

import android.widget.Magnifier;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;

/* loaded from: classes.dex */
public class F0 implements D0 {
    public final Magnifier a;

    public F0(Magnifier magnifier) {
        this.a = magnifier;
    }

    @Override // androidx.compose.foundation.D0
    public void a(long j, long j2) {
        this.a.show(androidx.compose.ui.geometry.b.d(j), androidx.compose.ui.geometry.b.e(j));
    }

    public final void b() {
        this.a.dismiss();
    }

    public final long c() {
        return R5.a(this.a.getWidth(), this.a.getHeight());
    }

    public final void d() {
        this.a.update();
    }
}
