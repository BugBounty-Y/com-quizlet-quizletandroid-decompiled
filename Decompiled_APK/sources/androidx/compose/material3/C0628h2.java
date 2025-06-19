package androidx.compose.material3;

import android.content.Context;
import android.os.Build;
import androidx.compose.animation.C0281h;
import androidx.compose.animation.core.C0238e;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AbstractC0930a;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.h2, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0628h2 extends AbstractC0930a {
    public final boolean a;
    public final Function0 b;
    public final C0238e c;
    public final kotlinx.coroutines.C d;
    public final InterfaceC0773a0 e;
    public Object f;
    public boolean g;

    public C0628h2(Context context, Function0 function0, C0238e c0238e, kotlinx.coroutines.C c) {
        super(context, null);
        this.a = true;
        this.b = function0;
        this.c = c0238e;
        this.d = c;
        this.e = C0776c.z(AbstractC0632i0.a);
    }

    @Override // androidx.compose.ui.platform.AbstractC0930a
    public final void Content(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(576708319);
        if ((((c0814p.h(this) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            ((Function2) ((androidx.compose.runtime.L0) this.e).getValue()).invoke(c0814p, 0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0281h(this, i, 16);
        }
    }

    @Override // androidx.compose.ui.platform.AbstractC0930a
    public final boolean getShouldCreateCompositionOnAttachedToWindow() {
        return this.g;
    }

    @Override // androidx.compose.ui.platform.AbstractC0930a, android.view.ViewGroup, android.view.View
    public final void onAttachedToWindow() {
        int i;
        super.onAttachedToWindow();
        if (!this.a || (i = Build.VERSION.SDK_INT) < 33) {
            return;
        }
        if (this.f == null) {
            Function0 function0 = this.b;
            this.f = i >= 34 ? androidx.activity.t.r(AbstractC0622g2.a(function0, this.c, this.d)) : AbstractC0592b2.a(function0);
        }
        AbstractC0592b2.b(this, this.f);
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        if (Build.VERSION.SDK_INT >= 33) {
            AbstractC0592b2.c(this, this.f);
        }
        this.f = null;
    }
}
