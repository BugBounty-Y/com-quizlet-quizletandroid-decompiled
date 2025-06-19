package com.braze.dispatch;

import com.braze.managers.C1500m;
import com.braze.managers.z;
import com.braze.storage.f0;
import com.braze.storage.t;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class n implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.braze.models.i b;

    public /* synthetic */ n(com.braze.models.i iVar, int i) {
        this.a = i;
        this.b = iVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return h.a(this.b);
            case 1:
                return C1500m.b(this.b);
            case 2:
                return C1500m.c(this.b);
            case 3:
                return C1500m.d(this.b);
            case 4:
                return C1500m.e(this.b);
            case 5:
                return C1500m.f(this.b);
            case 6:
                return C1500m.g(this.b);
            case 7:
                return z.b(this.b);
            case 8:
                return f0.c(this.b);
            default:
                return t.b(this.b);
        }
    }
}
