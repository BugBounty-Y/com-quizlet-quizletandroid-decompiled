package com.sdk.growthbook.features;

import com.sdk.growthbook.utils.Resource;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ FeaturesViewModel b;

    public /* synthetic */ c(FeaturesViewModel featuresViewModel, int i) {
        this.a = i;
        this.b = featuresViewModel;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                return FeaturesViewModel.handleFetchFeaturesWithRemoteEval$lambda$0(this.b, (Resource.Success) obj);
            case 1:
                return FeaturesViewModel.handleFetchFeaturesWithRemoteEval$lambda$1(this.b, (Resource.Error) obj);
            case 2:
                return FeaturesViewModel.handleFetchFeaturesWithRemoteEval$lambda$2(this.b, (FeaturesDataModel) obj);
            case 3:
                return FeaturesViewModel.handleFetchFeaturesWithRemoteEval$lambda$3(this.b, (Throwable) obj);
            case 4:
                return FeaturesViewModel.autoRefreshFeatures$lambda$8(this.b, (FeaturesDataModel) obj);
            default:
                return FeaturesViewModel.autoRefreshFeatures$lambda$9(this.b, (Throwable) obj);
        }
    }
}
