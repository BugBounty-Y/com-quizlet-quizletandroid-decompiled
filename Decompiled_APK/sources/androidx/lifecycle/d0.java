package androidx.lifecycle;

import android.os.Handler;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class d0 implements J {
    public static final d0 i = new d0();
    public int a;
    public int b;
    public Handler e;
    public boolean c = true;
    public boolean d = true;
    public final L f = new L(this);
    public final androidx.compose.ui.text.input.C g = new androidx.compose.ui.text.input.C(this, 7);
    public final A0 h = new A0(this);

    public final void a() {
        int i2 = this.b + 1;
        this.b = i2;
        if (i2 == 1) {
            if (this.c) {
                this.f.e(A.ON_RESUME);
                this.c = false;
            } else {
                Handler handler = this.e;
                Intrinsics.d(handler);
                handler.removeCallbacks(this.g);
            }
        }
    }

    @Override // androidx.lifecycle.J
    public final C getLifecycle() {
        return this.f;
    }
}
