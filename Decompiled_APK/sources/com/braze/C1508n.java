package com.braze;

import android.app.Activity;
import kotlin.jvm.functions.Function0;

/* renamed from: com.braze.n, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C1508n implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Activity b;
    public final /* synthetic */ Braze c;

    public /* synthetic */ C1508n(Activity activity, Braze braze, int i) {
        this.a = i;
        this.b = activity;
        this.c = braze;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Braze.closeSession$lambda$43(this.b, this.c);
            default:
                return Braze.openSession$lambda$40(this.b, this.c);
        }
    }
}
