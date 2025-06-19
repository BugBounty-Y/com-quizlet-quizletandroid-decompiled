package androidx.loader.app;

import androidx.collection.W;
import androidx.lifecycle.w0;

/* loaded from: classes.dex */
public class f extends w0 {
    public static final e d = new e();
    public final W b = new W(0);
    public boolean c = false;

    @Override // androidx.lifecycle.w0
    public final void z() {
        W w = this.b;
        int iG = w.g();
        for (int i = 0; i < iG; i++) {
            ((c) w.h(i)).m();
        }
        int i2 = w.d;
        Object[] objArr = w.c;
        for (int i3 = 0; i3 < i2; i3++) {
            objArr[i3] = null;
        }
        w.d = 0;
        w.a = false;
    }
}
