package androidx.fragment.compose;

import androidx.compose.runtime.G;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.fragment.app.Fragment;
import kotlin.jvm.internal.F;

/* loaded from: classes.dex */
public final class b implements G {
    public final /* synthetic */ AbstractC1136h0 a;
    public final /* synthetic */ Fragment b;
    public final /* synthetic */ e c;
    public final /* synthetic */ F d;

    public b(AbstractC1136h0 abstractC1136h0, Fragment fragment, e eVar, F f) {
        this.a = abstractC1136h0;
        this.b = fragment;
        this.c = eVar;
        this.d = f;
    }

    @Override // androidx.compose.runtime.G
    public final void dispose() {
        Fragment fragment = this.b;
        AbstractC1136h0 abstractC1136h0 = this.a;
        this.c.a.setValue(abstractC1136h0.d0(fragment));
        if (this.d.a) {
            C1121a c1121a = new C1121a(abstractC1136h0);
            c1121a.k(fragment);
            if (c1121a.g) {
                throw new IllegalStateException("This transaction is already being added to the back stack");
            }
            c1121a.h = false;
            c1121a.r.B(c1121a, true);
            return;
        }
        if (abstractC1136h0.R()) {
            return;
        }
        C1121a c1121a2 = new C1121a(abstractC1136h0);
        c1121a2.k(fragment);
        if (c1121a2.g) {
            throw new IllegalStateException("This transaction is already being added to the back stack");
        }
        c1121a2.h = false;
        c1121a2.r.B(c1121a2, false);
    }
}
