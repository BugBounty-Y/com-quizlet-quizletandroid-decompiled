package com.braze;

import com.braze.configuration.BrazeConfig;
import com.braze.configuration.RuntimeAppConfigurationProvider;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class D implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ BrazeConfig b;

    public /* synthetic */ D(BrazeConfig brazeConfig, int i) {
        this.a = i;
        this.b = brazeConfig;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Braze.applyPendingRuntimeConfiguration$lambda$195$lambda$194(this.b);
            default:
                return RuntimeAppConfigurationProvider.setConfiguration$lambda$0(this.b);
        }
    }
}
