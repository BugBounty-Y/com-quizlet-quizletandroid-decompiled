package com.braze;

import com.braze.configuration.CachedConfigurationProvider;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class X implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ Object c;

    public /* synthetic */ X(String str, int i, Object obj) {
        this.a = i;
        this.b = str;
        this.c = obj;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeUser.i(this.c, this.b);
            case 1:
                return BrazeUser.k(this.c, this.b);
            case 2:
                return CachedConfigurationProvider.getResourceConfigurationValue$lambda$1(this.b, this.c);
            case 3:
                return CachedConfigurationProvider.getRuntimeConfigurationValue$lambda$0(this.b, this.c);
            case 4:
                return CachedConfigurationProvider.readResourceValue$lambda$2(this.b, this.c);
            case 5:
                return com.braze.storage.h0.d(this.b, this.c);
            default:
                return com.braze.storage.h0.b(this.b, this.c);
        }
    }
}
