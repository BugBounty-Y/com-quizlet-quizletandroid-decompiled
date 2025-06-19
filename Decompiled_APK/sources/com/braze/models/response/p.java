package com.braze.models.response;

import com.braze.storage.e0;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class p implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ m b;

    public /* synthetic */ p(m mVar, int i) {
        this.a = i;
        this.b = mVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return m.a(this.b);
            default:
                return e0.b(this.b);
        }
    }
}
