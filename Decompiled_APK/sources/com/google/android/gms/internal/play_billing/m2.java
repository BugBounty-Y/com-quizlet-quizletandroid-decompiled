package com.google.android.gms.internal.play_billing;

import java.io.Serializable;

/* loaded from: classes2.dex */
public final class m2 {
    public Serializable a;
    public o2 b;
    public p2 c;
    public boolean d;

    public final void finalize() {
        p2 p2Var;
        o2 o2Var = this.b;
        if (o2Var != null) {
            n2 n2Var = o2Var.b;
            if (!n2Var.isDone()) {
                if (l2.f.w(n2Var, null, new C3811k1(new androidx.concurrent.futures.b("The completer object was garbage collected - this future would otherwise never complete. The tag was: ".concat(String.valueOf(this.a)), 4)))) {
                    l2.d(n2Var);
                }
            }
        }
        if (this.d || (p2Var = this.c) == null) {
            return;
        }
        p2Var.i(null);
    }
}
