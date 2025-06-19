package com.sdk.growthbook.features;

import androidx.datastore.core.C1087t;
import com.google.android.gms.internal.mlkit_vision_camera.Y1;
import com.quizlet.qutils.android.f;
import com.sdk.growthbook.GrowthBookSDK;
import com.sdk.growthbook.network.NetworkDispatcher;
import com.sdk.growthbook.serializable_model.SerializableFeaturesDataModel;
import com.sdk.growthbook.serializable_model.SerializableFeaturesDataModelKt;
import com.sdk.growthbook.utils.FeatureRefreshStrategy;
import com.sdk.growthbook.utils.GBRemoteEvalParams;
import com.sdk.growthbook.utils.Resource;
import java.util.LinkedHashMap;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.serialization.json.g;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class FeaturesDataSource {

    @NotNull
    private final NetworkDispatcher dispatcher;
    private final boolean enableLogging;

    public FeaturesDataSource(@NotNull NetworkDispatcher dispatcher, boolean z) {
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.dispatcher = dispatcher;
        this.enableLogging = z;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit _get_jsonParser_$lambda$0(g Json) {
        Intrinsics.checkNotNullParameter(Json, "$this$Json");
        Json.e = true;
        Json.d = true;
        Json.c = true;
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit fetchFeatures$lambda$1(FeaturesDataSource this$0, Function1 success, String rawContent) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(success, "$success");
        Intrinsics.checkNotNullParameter(rawContent, "rawContent");
        success.invoke(SerializableFeaturesDataModelKt.gbDeserialize((SerializableFeaturesDataModel) this$0.getJsonParser().b(rawContent, SerializableFeaturesDataModel.Companion.serializer())));
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit fetchFeatures$lambda$2(Function1 failure, Throwable apiTimeError) {
        Intrinsics.checkNotNullParameter(failure, "$failure");
        Intrinsics.checkNotNullParameter(apiTimeError, "apiTimeError");
        failure.invoke(apiTimeError);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit fetchRemoteEval$lambda$5(FeaturesDataSource this$0, Function1 success, String rawContent) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(success, "$success");
        Intrinsics.checkNotNullParameter(rawContent, "rawContent");
        success.invoke(new Resource.Success(SerializableFeaturesDataModelKt.gbDeserialize((SerializableFeaturesDataModel) this$0.getJsonParser().b(rawContent, SerializableFeaturesDataModel.Companion.serializer()))));
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit fetchRemoteEval$lambda$6(Function1 failure, Throwable error) {
        Intrinsics.checkNotNullParameter(failure, "$failure");
        Intrinsics.checkNotNullParameter(error, "error");
        failure.invoke(new Resource.Error(new Exception(error.getMessage())));
        return Unit.a;
    }

    private final String getEndpoint(FeatureRefreshStrategy featureRefreshStrategy) {
        FeatureURLBuilder featureURLBuilder = new FeatureURLBuilder();
        GrowthBookSDK.Companion companion = GrowthBookSDK.Companion;
        return featureURLBuilder.buildUrl(companion.getGbContext$GrowthBook_release().getHostURL(), companion.getGbContext$GrowthBook_release().getApiKey(), featureRefreshStrategy);
    }

    public static /* synthetic */ String getEndpoint$default(FeaturesDataSource featuresDataSource, FeatureRefreshStrategy featureRefreshStrategy, int i, Object obj) {
        if ((i & 1) != 0) {
            featureRefreshStrategy = FeatureRefreshStrategy.STALE_WHILE_REVALIDATE;
        }
        return featuresDataSource.getEndpoint(featureRefreshStrategy);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final kotlinx.serialization.json.c getJsonParser() {
        return Y1.c(new f(27));
    }

    @NotNull
    public final InterfaceC4992i autoRefresh(@NotNull Function1<? super FeaturesDataModel, Unit> success, @NotNull Function1<? super Throwable, Unit> failure) {
        Intrinsics.checkNotNullParameter(success, "success");
        Intrinsics.checkNotNullParameter(failure, "failure");
        return new C1087t(new FeaturesDataSource$autoRefresh$$inlined$transform$1(this.dispatcher.consumeSSEConnection(getEndpoint(FeatureRefreshStrategy.SERVER_SENT_EVENTS)), null, this, success, failure));
    }

    public final void fetchFeatures(@NotNull Function1<? super FeaturesDataModel, Unit> success, @NotNull Function1<? super Throwable, Unit> failure) {
        Intrinsics.checkNotNullParameter(success, "success");
        Intrinsics.checkNotNullParameter(failure, "failure");
        int i = 0;
        this.dispatcher.consumeGETRequest(getEndpoint$default(this, null, 1, null), new a(this, success, i), new b(i, failure));
    }

    public final void fetchRemoteEval(GBRemoteEvalParams gBRemoteEvalParams, @NotNull Function1<? super Resource.Success<FeaturesDataModel>, Unit> success, @NotNull Function1<? super Resource.Error, Unit> failure) {
        Intrinsics.checkNotNullParameter(success, "success");
        Intrinsics.checkNotNullParameter(failure, "failure");
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        if (gBRemoteEvalParams != null) {
            linkedHashMap.put("attributes", gBRemoteEvalParams.getAttributes());
            linkedHashMap.put("forcedFeatures", gBRemoteEvalParams.getForcedFeatures());
            linkedHashMap.put("forcedVariations", gBRemoteEvalParams.getForcedVariations());
        }
        if (this.enableLogging) {
            System.out.println(linkedHashMap);
        }
        int i = 1;
        this.dispatcher.consumePOSTRequest(getEndpoint(FeatureRefreshStrategy.SERVER_SENT_REMOTE_FEATURE_EVAL), linkedHashMap, new a(this, success, i), new b(i, failure));
    }

    public /* synthetic */ FeaturesDataSource(NetworkDispatcher networkDispatcher, boolean z, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(networkDispatcher, (i & 2) != 0 ? true : z);
    }
}
