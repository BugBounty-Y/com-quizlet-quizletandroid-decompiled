package com.sdk.growthbook.features;

import com.sdk.growthbook.model.GBFeature;
import com.sdk.growthbook.sandbox.CachingImpl;
import com.sdk.growthbook.sandbox.KMMCachingKt;
import com.sdk.growthbook.serializable_model.SerializableFeaturesDataModel;
import com.sdk.growthbook.serializable_model.SerializableFeaturesDataModelKt;
import com.sdk.growthbook.utils.Constants;
import com.sdk.growthbook.utils.CryptoKt;
import com.sdk.growthbook.utils.DefaultCrypto;
import com.sdk.growthbook.utils.GBError;
import com.sdk.growthbook.utils.GBRemoteEvalParams;
import com.sdk.growthbook.utils.Resource;
import java.util.Map;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.serialization.json.v;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class FeaturesViewModel {

    @NotNull
    private final FeaturesDataSource dataSource;

    @NotNull
    private final FeaturesFlowDelegate delegate;
    private final String encryptionKey;

    @NotNull
    private final CachingImpl manager;

    public FeaturesViewModel(@NotNull FeaturesFlowDelegate delegate, @NotNull FeaturesDataSource dataSource, String str) {
        Intrinsics.checkNotNullParameter(delegate, "delegate");
        Intrinsics.checkNotNullParameter(dataSource, "dataSource");
        this.delegate = delegate;
        this.dataSource = dataSource;
        this.encryptionKey = str;
        this.manager = CachingImpl.INSTANCE;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit autoRefreshFeatures$lambda$8(FeaturesViewModel this$0, FeaturesDataModel dataModel) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(dataModel, "dataModel");
        this$0.prepareFeaturesDataForRemoteEval(dataModel);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit autoRefreshFeatures$lambda$9(FeaturesViewModel this$0, Throwable th) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.delegate.featuresFetchFailed(new GBError(th), true);
        return Unit.a;
    }

    public static /* synthetic */ void fetchFeatures$default(FeaturesViewModel featuresViewModel, boolean z, GBRemoteEvalParams gBRemoteEvalParams, int i, Object obj) {
        if ((i & 1) != 0) {
            z = false;
        }
        if ((i & 2) != 0) {
            gBRemoteEvalParams = null;
        }
        featuresViewModel.fetchFeatures(z, gBRemoteEvalParams);
    }

    private final FeaturesDataModel getDataFromCache() {
        SerializableFeaturesDataModel serializableFeaturesDataModel = (SerializableFeaturesDataModel) KMMCachingKt.getData(this.manager.getLayer(), Constants.FEATURE_CACHE, SerializableFeaturesDataModel.Companion.serializer());
        if (serializableFeaturesDataModel != null) {
            return SerializableFeaturesDataModelKt.gbDeserialize(serializableFeaturesDataModel);
        }
        return null;
    }

    private final void handleFetchFeaturesWithRemoteEval(boolean z, GBRemoteEvalParams gBRemoteEvalParams) {
        if (z) {
            this.dataSource.fetchRemoteEval(gBRemoteEvalParams, new c(this, 0), new c(this, 1));
        } else {
            this.dataSource.fetchFeatures(new c(this, 2), new c(this, 3));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit handleFetchFeaturesWithRemoteEval$lambda$0(FeaturesViewModel this$0, Resource.Success responseFeaturesDataModel) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(responseFeaturesDataModel, "responseFeaturesDataModel");
        this$0.prepareFeaturesDataForRemoteEval((FeaturesDataModel) responseFeaturesDataModel.getData());
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit handleFetchFeaturesWithRemoteEval$lambda$1(FeaturesViewModel this$0, Resource.Error error) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(error, "error");
        this$0.delegate.featuresFetchFailed(new GBError(error.getException()), true);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit handleFetchFeaturesWithRemoteEval$lambda$2(FeaturesViewModel this$0, FeaturesDataModel dataModel) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(dataModel, "dataModel");
        this$0.prepareFeaturesDataForRemoteEval(dataModel);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit handleFetchFeaturesWithRemoteEval$lambda$3(FeaturesViewModel this$0, Throwable th) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.delegate.featuresFetchFailed(new GBError(th), true);
        return Unit.a;
    }

    private final void handleFetchFeaturesWithoutRemoteEval(FeaturesDataModel featuresDataModel) {
        String str;
        Map<String, GBFeature> featuresFromEncryptedFeatures$default;
        Map<String, GBFeature> features = featuresDataModel.getFeatures();
        if (features != null) {
            this.delegate.featuresFetchedSuccessfully(features, false);
        }
        String encryptedFeatures = featuresDataModel.getEncryptedFeatures();
        if (encryptedFeatures == null || (str = this.encryptionKey) == null || (featuresFromEncryptedFeatures$default = CryptoKt.getFeaturesFromEncryptedFeatures$default(encryptedFeatures, str, null, 4, null)) == null) {
            return;
        }
        this.delegate.featuresFetchedSuccessfully(featuresFromEncryptedFeatures$default, false);
    }

    private final void prepareFeaturesDataForRemoteEval(FeaturesDataModel featuresDataModel) {
        String str;
        String str2;
        Map<String, GBFeature> features = featuresDataModel != null ? featuresDataModel.getFeatures() : null;
        v savedGroups = featuresDataModel != null ? featuresDataModel.getSavedGroups() : null;
        String encryptedFeatures = featuresDataModel != null ? featuresDataModel.getEncryptedFeatures() : null;
        String encryptedSavedGroups = featuresDataModel != null ? featuresDataModel.getEncryptedSavedGroups() : null;
        if (featuresDataModel != null) {
            try {
                putDataToCache(featuresDataModel);
                this.delegate.featuresAPIModelSuccessfully(featuresDataModel);
                if (features != null && !features.isEmpty()) {
                    this.delegate.featuresFetchedSuccessfully(features, true);
                    return;
                }
                if (encryptedFeatures == null || (str = this.encryptionKey) == null) {
                    this.delegate.featuresFetchFailed(new GBError(new Exception()), true);
                    return;
                }
                if (str.length() > 0) {
                    Map<String, GBFeature> featuresFromEncryptedFeatures = CryptoKt.getFeaturesFromEncryptedFeatures(encryptedFeatures, this.encryptionKey, new DefaultCrypto());
                    if (featuresFromEncryptedFeatures == null) {
                        return;
                    }
                    this.delegate.featuresFetchedSuccessfully(featuresFromEncryptedFeatures, true);
                    return;
                }
                if (features != null) {
                    this.delegate.featuresFetchedSuccessfully(features, true);
                    return;
                }
                if (savedGroups != null && !savedGroups.isEmpty()) {
                    this.delegate.savedGroupsFetchedSuccessfully(savedGroups, true);
                    return;
                }
                if (encryptedSavedGroups == null || (str2 = this.encryptionKey) == null) {
                    this.delegate.savedGroupsFetchFailed(new GBError(new Exception()), true);
                    return;
                }
                if (str2.length() <= 0) {
                    if (savedGroups != null) {
                        this.delegate.savedGroupsFetchedSuccessfully(savedGroups, true);
                    }
                } else {
                    v savedGroupFromEncryptedSavedGroup = CryptoKt.getSavedGroupFromEncryptedSavedGroup(encryptedSavedGroups, this.encryptionKey, new DefaultCrypto());
                    if (savedGroupFromEncryptedSavedGroup == null) {
                        return;
                    }
                    this.delegate.savedGroupsFetchedSuccessfully(savedGroupFromEncryptedSavedGroup, true);
                }
            } catch (Throwable th) {
                this.delegate.featuresFetchFailed(new GBError(th), true);
            }
        }
    }

    private final void putDataToCache(FeaturesDataModel featuresDataModel) {
        KMMCachingKt.putData(this.manager.getLayer(), Constants.FEATURE_CACHE, FeaturesDataModelKt.gbSerialize(featuresDataModel), SerializableFeaturesDataModel.Companion.serializer());
    }

    @NotNull
    public final InterfaceC4992i autoRefreshFeatures() {
        return this.dataSource.autoRefresh(new c(this, 4), new c(this, 5));
    }

    public final void fetchFeatures(boolean z, GBRemoteEvalParams gBRemoteEvalParams) {
        try {
            FeaturesDataModel dataFromCache = getDataFromCache();
            if (dataFromCache != null) {
                handleFetchFeaturesWithoutRemoteEval(dataFromCache);
            }
        } catch (Throwable th) {
            this.delegate.featuresFetchFailed(new GBError(th), false);
        }
        handleFetchFeaturesWithRemoteEval(z, gBRemoteEvalParams);
    }

    public /* synthetic */ FeaturesViewModel(FeaturesFlowDelegate featuresFlowDelegate, FeaturesDataSource featuresDataSource, String str, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(featuresFlowDelegate, featuresDataSource, (i & 4) != 0 ? null : str);
    }
}
