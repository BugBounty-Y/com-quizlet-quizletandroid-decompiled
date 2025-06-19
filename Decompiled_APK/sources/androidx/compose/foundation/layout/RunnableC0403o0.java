package androidx.compose.foundation.layout;

import android.os.Build;
import android.view.View;
import androidx.core.view.AbstractC1047f0;
import androidx.core.view.InterfaceC1062t;
import java.util.List;

/* renamed from: androidx.compose.foundation.layout.o0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class RunnableC0403o0 extends AbstractC1047f0 implements Runnable, InterfaceC1062t, View.OnAttachStateChangeListener {
    public final S0 c;
    public boolean d;
    public boolean e;
    public androidx.core.view.D0 f;

    public RunnableC0403o0(S0 s0) {
        super(!s0.t ? 1 : 0);
        this.c = s0;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final void d(androidx.core.view.m0 m0Var) {
        this.d = false;
        this.e = false;
        androidx.core.view.D0 d0 = this.f;
        if (m0Var.a.a() != 0 && d0 != null) {
            S0 s0 = this.c;
            s0.getClass();
            androidx.core.view.z0 z0Var = d0.a;
            s0.s.f(AbstractC0382e.A(z0Var.g(8)));
            s0.r.f(AbstractC0382e.A(z0Var.g(8)));
            S0.a(s0, d0);
        }
        this.f = null;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final void e() {
        this.d = true;
        this.e = true;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final androidx.core.view.D0 f(androidx.core.view.D0 d0, List list) {
        S0 s0 = this.c;
        S0.a(s0, d0);
        return s0.t ? androidx.core.view.D0.b : d0;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final androidx.work.impl.model.e g(androidx.work.impl.model.e eVar) {
        this.d = false;
        return eVar;
    }

    @Override // android.view.View.OnAttachStateChangeListener
    public final void onViewAttachedToWindow(View view) {
        view.requestApplyInsets();
    }

    @Override // android.view.View.OnAttachStateChangeListener
    public final void onViewDetachedFromWindow(View view) {
    }

    @Override // java.lang.Runnable
    public final void run() {
        if (this.d) {
            this.d = false;
            this.e = false;
            androidx.core.view.D0 d0 = this.f;
            if (d0 != null) {
                S0 s0 = this.c;
                s0.getClass();
                s0.s.f(AbstractC0382e.A(d0.a.g(8)));
                S0.a(s0, d0);
                this.f = null;
            }
        }
    }

    @Override // androidx.core.view.InterfaceC1062t
    public final androidx.core.view.D0 w(androidx.core.view.D0 d0, View view) {
        this.f = d0;
        S0 s0 = this.c;
        s0.getClass();
        androidx.core.view.z0 z0Var = d0.a;
        s0.r.f(AbstractC0382e.A(z0Var.g(8)));
        if (this.d) {
            if (Build.VERSION.SDK_INT == 30) {
                view.post(this);
            }
        } else if (!this.e) {
            s0.s.f(AbstractC0382e.A(z0Var.g(8)));
            S0.a(s0, d0);
        }
        return s0.t ? androidx.core.view.D0.b : d0;
    }
}
