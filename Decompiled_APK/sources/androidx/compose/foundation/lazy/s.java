package androidx.compose.foundation.lazy;

import androidx.compose.animation.d0;
import androidx.compose.foundation.lazy.layout.X;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.H0;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class s {
    public final /* synthetic */ int a;
    public final H0 b;
    public final H0 c;
    public boolean d;
    public Object e;
    public final X f;

    public s(int i, int i2, int i3) {
        this.a = i3;
        switch (i3) {
            case 1:
                this.b = C0776c.w(i);
                this.c = C0776c.w(i2);
                this.f = new X(i, 90, 200);
                break;
            default:
                this.b = C0776c.w(i);
                this.c = C0776c.w(i2);
                this.f = new X(i, 30, 100);
                break;
        }
    }

    public final int a() {
        switch (this.a) {
        }
        return this.b.i();
    }

    public final int b() {
        switch (this.a) {
        }
        return this.c.i();
    }

    public final void c(int i, int i2) {
        switch (this.a) {
            case 0:
                if (i < DefinitionKt.NO_Float_VALUE) {
                    throw new IllegalArgumentException(d0.m(')', i, "Index should be non-negative (").toString());
                }
                this.b.j(i);
                this.f.a(i);
                this.c.j(i2);
                return;
            default:
                if (i < DefinitionKt.NO_Float_VALUE) {
                    throw new IllegalArgumentException(d0.m(')', i, "Index should be non-negative (").toString());
                }
                this.b.j(i);
                this.f.a(i);
                this.c.j(i2);
                return;
        }
    }
}
