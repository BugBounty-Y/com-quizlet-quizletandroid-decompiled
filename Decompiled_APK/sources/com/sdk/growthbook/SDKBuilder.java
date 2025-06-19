package com.sdk.growthbook;

import com.sdk.growthbook.model.GBExperiment;
import com.sdk.growthbook.model.GBExperimentResult;
import com.sdk.growthbook.model.GBValue;
import com.sdk.growthbook.network.NetworkDispatcher;
import java.util.HashMap;
import java.util.Map;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public abstract class SDKBuilder {

    @NotNull
    private final String apiKey;

    @NotNull
    private final Map<String, GBValue> attributes;
    private final boolean enableLogging;
    private boolean enabled;
    private final String encryptionKey;

    @NotNull
    private Map<String, Integer> forcedVariations;

    @NotNull
    private final String hostURL;

    @NotNull
    private final NetworkDispatcher networkDispatcher;
    private boolean qaMode;
    private final boolean remoteEval;

    @NotNull
    private final Function2<GBExperiment, GBExperimentResult, Unit> trackingCallback;

    /* JADX WARN: Multi-variable type inference failed */
    public SDKBuilder(@NotNull String apiKey, @NotNull String hostURL, @NotNull Map<String, ? extends GBValue> attributes, @NotNull Function2<? super GBExperiment, ? super GBExperimentResult, Unit> trackingCallback, String str, @NotNull NetworkDispatcher networkDispatcher, boolean z, boolean z2) {
        Intrinsics.checkNotNullParameter(apiKey, "apiKey");
        Intrinsics.checkNotNullParameter(hostURL, "hostURL");
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(trackingCallback, "trackingCallback");
        Intrinsics.checkNotNullParameter(networkDispatcher, "networkDispatcher");
        this.apiKey = apiKey;
        this.hostURL = hostURL;
        this.attributes = attributes;
        this.trackingCallback = trackingCallback;
        this.encryptionKey = str;
        this.networkDispatcher = networkDispatcher;
        this.remoteEval = z;
        this.enableLogging = z2;
        this.forcedVariations = new HashMap();
        this.enabled = true;
    }

    @NotNull
    public final String getApiKey() {
        return this.apiKey;
    }

    @NotNull
    public final Map<String, GBValue> getAttributes() {
        return this.attributes;
    }

    public final boolean getEnableLogging() {
        return this.enableLogging;
    }

    public final boolean getEnabled$GrowthBook_release() {
        return this.enabled;
    }

    public final String getEncryptionKey() {
        return this.encryptionKey;
    }

    @NotNull
    public final Map<String, Integer> getForcedVariations$GrowthBook_release() {
        return this.forcedVariations;
    }

    @NotNull
    public final String getHostURL() {
        return this.hostURL;
    }

    @NotNull
    public final NetworkDispatcher getNetworkDispatcher() {
        return this.networkDispatcher;
    }

    public final boolean getQaMode$GrowthBook_release() {
        return this.qaMode;
    }

    public final boolean getRemoteEval() {
        return this.remoteEval;
    }

    @NotNull
    public final Function2<GBExperiment, GBExperimentResult, Unit> getTrackingCallback() {
        return this.trackingCallback;
    }

    @NotNull
    public abstract GrowthBookSDK initialize();

    @NotNull
    public final SDKBuilder setEnabled(boolean z) {
        this.enabled = z;
        return this;
    }

    public final void setEnabled$GrowthBook_release(boolean z) {
        this.enabled = z;
    }

    @NotNull
    public final SDKBuilder setForcedVariations(@NotNull Map<String, Integer> forcedVariations) {
        Intrinsics.checkNotNullParameter(forcedVariations, "forcedVariations");
        this.forcedVariations = forcedVariations;
        return this;
    }

    public final void setForcedVariations$GrowthBook_release(@NotNull Map<String, Integer> map) {
        Intrinsics.checkNotNullParameter(map, "<set-?>");
        this.forcedVariations = map;
    }

    @NotNull
    public final SDKBuilder setQAMode(boolean z) {
        this.qaMode = z;
        return this;
    }

    public final void setQaMode$GrowthBook_release(boolean z) {
        this.qaMode = z;
    }
}
