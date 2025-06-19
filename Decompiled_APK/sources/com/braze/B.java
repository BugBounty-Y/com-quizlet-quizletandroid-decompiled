package com.braze;

import com.braze.managers.C1500m;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class B implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Throwable b;

    public /* synthetic */ B(int i, Throwable th) {
        this.a = i;
        this.b = th;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Braze.publishError$lambda$213(this.b);
            default:
                return C1500m.b(this.b);
        }
    }
}
