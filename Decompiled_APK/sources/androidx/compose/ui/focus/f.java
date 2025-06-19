package androidx.compose.ui.focus;

import androidx.activity.K;
import androidx.collection.J;
import androidx.collection.U;
import androidx.compose.foundation.text.z0;

/* loaded from: classes.dex */
public final class f {
    public final z0 a;
    public final K b;
    public final J c;
    public final J d;
    public final J e;
    public final J f;

    public f(z0 z0Var, K k) {
        this.a = z0Var;
        this.b = k;
        int i = U.a;
        this.c = new J();
        this.d = new J();
        this.e = new J();
        this.f = new J();
    }

    public final boolean a() {
        return this.c.h() || this.e.h() || this.d.h();
    }

    public final void b(J j, Object obj) {
        if (j.a(obj) && this.c.d + this.d.d + this.e.d == 1) {
            this.a.invoke(new K(0, this, f.class, "invalidateNodes", "invalidateNodes()V", 0, 4));
        }
    }
}
