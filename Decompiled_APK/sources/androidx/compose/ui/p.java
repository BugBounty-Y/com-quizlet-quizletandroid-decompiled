package androidx.compose.ui;

import androidx.compose.foundation.Q;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.InterfaceC0917m;
import androidx.compose.ui.node.a0;
import androidx.compose.ui.node.d0;
import androidx.compose.ui.platform.C0971v;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import kotlinx.coroutines.C;
import kotlinx.coroutines.C5023i0;
import kotlinx.coroutines.C5027k0;
import kotlinx.coroutines.E;
import kotlinx.coroutines.InterfaceC5025j0;

/* loaded from: classes.dex */
public abstract class p implements InterfaceC0917m {
    public kotlinx.coroutines.internal.d b;
    public int c;
    public p e;
    public p f;
    public d0 g;
    public a0 h;
    public boolean i;
    public boolean j;
    public boolean k;
    public boolean l;
    public boolean m;
    public p a = this;
    public int d = -1;

    public final C A0() {
        kotlinx.coroutines.internal.d dVar = this.b;
        if (dVar != null) {
            return dVar;
        }
        kotlinx.coroutines.internal.d dVarC = E.c(((C0971v) AbstractC0910f.w(this)).getCoroutineContext().plus(new C5027k0((InterfaceC5025j0) ((C0971v) AbstractC0910f.w(this)).getCoroutineContext().get(C5023i0.a))));
        this.b = dVarC;
        return dVarC;
    }

    public boolean B0() {
        return !(this instanceof Q);
    }

    public void C0() {
        if (this.m) {
            W4.f("node attached multiple times");
            throw null;
        }
        if (this.h == null) {
            W4.f("attach invoked on a node without a coordinator");
            throw null;
        }
        this.m = true;
        this.k = true;
    }

    public void D0() {
        if (!this.m) {
            W4.f("Cannot detach a node that is not attached");
            throw null;
        }
        if (this.k) {
            W4.f("Must run runAttachLifecycle() before markAsDetached()");
            throw null;
        }
        if (this.l) {
            W4.f("Must run runDetachLifecycle() before markAsDetached()");
            throw null;
        }
        this.m = false;
        kotlinx.coroutines.internal.d dVar = this.b;
        if (dVar != null) {
            E.i(dVar, new ModifierNodeDetachedCancellationException());
            this.b = null;
        }
    }

    public void E0() {
    }

    public void F0() {
    }

    public void G0() {
    }

    public void H0() {
        if (this.m) {
            G0();
        } else {
            W4.f("reset() called on an unattached node");
            throw null;
        }
    }

    public void I0() {
        if (!this.m) {
            W4.f("Must run markAsAttached() prior to runAttachLifecycle");
            throw null;
        }
        if (!this.k) {
            W4.f("Must run runAttachLifecycle() only once after markAsAttached()");
            throw null;
        }
        this.k = false;
        E0();
        this.l = true;
    }

    public void J0() {
        if (!this.m) {
            W4.f("node detached multiple times");
            throw null;
        }
        if (this.h == null) {
            W4.f("detach invoked on a node without a coordinator");
            throw null;
        }
        if (!this.l) {
            W4.f("Must run runDetachLifecycle() once after runAttachLifecycle() and before markAsDetached()");
            throw null;
        }
        this.l = false;
        F0();
    }

    public void K0(p pVar) {
        this.a = pVar;
    }

    public void L0(a0 a0Var) {
        this.h = a0Var;
    }
}
