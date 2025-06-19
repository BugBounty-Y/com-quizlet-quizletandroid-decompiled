package androidx.fragment.compose;

import android.content.Context;
import android.os.Bundle;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.N;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.F;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class c extends r implements Function1 {
    public final /* synthetic */ AbstractC1136h0 a;
    public final /* synthetic */ d b;
    public final /* synthetic */ Context c;
    public final /* synthetic */ Class d;
    public final /* synthetic */ InterfaceC0773a0 e;
    public final /* synthetic */ e f;
    public final /* synthetic */ Bundle g;
    public final /* synthetic */ int h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(AbstractC1136h0 abstractC1136h0, d dVar, Context context, Class cls, InterfaceC0773a0 interfaceC0773a0, e eVar, Bundle bundle, int i) {
        super(1);
        this.a = abstractC1136h0;
        this.b = dVar;
        this.c = context;
        this.d = cls;
        this.e = interfaceC0773a0;
        this.f = eVar;
        this.g = bundle;
        this.h = i;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        F f = new F();
        d dVar = this.b;
        int id = dVar.a().getId();
        AbstractC1136h0 abstractC1136h0 = this.a;
        Fragment fragmentD = abstractC1136h0.D(id);
        e eVar = this.f;
        if (fragmentD == null) {
            N nL = abstractC1136h0.L();
            this.c.getClassLoader();
            fragmentD = nL.a(this.d.getName());
            fragmentD.setInitialSavedState((Fragment.SavedState) eVar.a.getValue());
            fragmentD.setArguments(this.g);
            C1121a c1121a = new C1121a(abstractC1136h0);
            c1121a.p = true;
            c1121a.b(dVar.a(), fragmentD, String.valueOf(this.h));
            boolean zR = abstractC1136h0.R();
            AbstractC1136h0 abstractC1136h02 = c1121a.r;
            if (zR) {
                f.a = true;
                fragmentD.getLifecycle().a(new a(f, fragmentD));
                if (c1121a.g) {
                    throw new IllegalStateException("This transaction is already being added to the back stack");
                }
                c1121a.h = false;
                abstractC1136h02.B(c1121a, true);
            } else {
                if (c1121a.g) {
                    throw new IllegalStateException("This transaction is already being added to the back stack");
                }
                c1121a.h = false;
                abstractC1136h02.B(c1121a, false);
            }
        }
        abstractC1136h0.U(dVar.a());
        ((Function1) this.e.getValue()).invoke(fragmentD);
        return new b(abstractC1136h0, fragmentD, eVar, f);
    }
}
