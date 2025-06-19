package androidx.compose.ui.platform;

import androidx.compose.runtime.C0833w;
import androidx.compose.runtime.InterfaceC0819s;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class t1 implements InterfaceC0819s, androidx.lifecycle.H {
    public final C0971v a;
    public final C0833w b;
    public boolean c;
    public androidx.lifecycle.C d;
    public androidx.compose.runtime.internal.d e = AbstractC0953l0.a;

    public t1(C0971v c0971v, C0833w c0833w) {
        this.a = c0971v;
        this.b = c0833w;
    }

    public final void a(Function2 function2) {
        this.a.setOnViewTreeOwnersAvailable(new androidx.compose.foundation.text.selection.n0(25, this, (androidx.compose.runtime.internal.d) function2));
    }

    @Override // androidx.lifecycle.H
    public final void d(androidx.lifecycle.J j, androidx.lifecycle.A a) {
        if (a == androidx.lifecycle.A.ON_DESTROY) {
            dispose();
        } else {
            if (a != androidx.lifecycle.A.ON_CREATE || this.c) {
                return;
            }
            a(this.e);
        }
    }

    @Override // androidx.compose.runtime.InterfaceC0819s
    public final void dispose() {
        if (!this.c) {
            this.c = true;
            this.a.getView().setTag(R.id.wrapped_composition_tag, null);
            androidx.lifecycle.C c = this.d;
            if (c != null) {
                c.b(this);
            }
        }
        this.b.dispose();
    }
}
