package androidx.fragment.app;

import android.os.Bundle;

/* loaded from: classes.dex */
public final class Z implements androidx.lifecycle.H {
    public final /* synthetic */ String a;
    public final /* synthetic */ m0 b;
    public final /* synthetic */ androidx.lifecycle.C c;
    public final /* synthetic */ AbstractC1136h0 d;

    public Z(AbstractC1136h0 abstractC1136h0, String str, m0 m0Var, androidx.lifecycle.C c) {
        this.d = abstractC1136h0;
        this.a = str;
        this.b = m0Var;
        this.c = c;
    }

    @Override // androidx.lifecycle.H
    public final void d(androidx.lifecycle.J j, androidx.lifecycle.A a) {
        Bundle bundle;
        androidx.lifecycle.A a2 = androidx.lifecycle.A.ON_START;
        String str = this.a;
        AbstractC1136h0 abstractC1136h0 = this.d;
        if (a == a2 && (bundle = (Bundle) abstractC1136h0.m.get(str)) != null) {
            this.b.y(bundle, str);
            abstractC1136h0.m.remove(str);
            AbstractC1136h0.N(2);
        }
        if (a == androidx.lifecycle.A.ON_DESTROY) {
            this.c.b(this);
            abstractC1136h0.n.remove(str);
        }
    }
}
