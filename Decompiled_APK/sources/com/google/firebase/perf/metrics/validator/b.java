package com.google.firebase.perf.metrics.validator;

import com.google.firebase.perf.v1.o;

/* loaded from: classes2.dex */
public final class b extends e {
    public final o a;

    public b(o oVar) {
        this.a = oVar;
    }

    @Override // com.google.firebase.perf.metrics.validator.e
    public final boolean a() {
        o oVar = this.a;
        if (!oVar.F()) {
            return false;
        }
        if (oVar.B() > 0 || oVar.A() > 0) {
            return true;
        }
        return oVar.E() && oVar.D().A();
    }
}
