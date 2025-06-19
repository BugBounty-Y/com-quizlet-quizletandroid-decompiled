package com.sdk.growthbook.features;

import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ FeaturesDataSource b;
    public final /* synthetic */ Function1 c;

    public /* synthetic */ a(FeaturesDataSource featuresDataSource, Function1 function1, int i) {
        this.a = i;
        this.b = featuresDataSource;
        this.c = function1;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        String str = (String) obj;
        switch (this.a) {
            case 0:
                return FeaturesDataSource.fetchFeatures$lambda$1(this.b, this.c, str);
            default:
                return FeaturesDataSource.fetchRemoteEval$lambda$5(this.b, this.c, str);
        }
    }
}
