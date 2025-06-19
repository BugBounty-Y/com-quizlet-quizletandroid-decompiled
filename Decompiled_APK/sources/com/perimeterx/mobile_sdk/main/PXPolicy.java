package com.perimeterx.mobile_sdk.main;

import androidx.annotation.Keep;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Keep
@Metadata
/* loaded from: classes2.dex */
public final class PXPolicy {
    private boolean allowDeviceMotionDetection;
    private boolean allowTouchDetection;
    private String doctorBypassMonitorHeader;
    private boolean doctorCheckEnabled;

    @NotNull
    private final HashMap<String, ArrayList<String>> domains;

    @NotNull
    private PXStorageMethod storageMethod;

    @NotNull
    private PXPolicyUrlRequestInterceptionType urlRequestInterceptionType;

    public PXPolicy() {
        this(null, null, null, false, false, null, false, 127, null);
    }

    @NotNull
    public final PXPolicy copy$PerimeterX_release() {
        PXPolicy pXPolicy = new PXPolicy(null, null, null, false, false, null, false, 127, null);
        pXPolicy.urlRequestInterceptionType = this.urlRequestInterceptionType;
        for (Map.Entry<String, ArrayList<String>> entry : this.domains.entrySet()) {
            pXPolicy.setDomains(entry.getValue(), entry.getKey());
        }
        pXPolicy.allowTouchDetection = this.allowTouchDetection;
        pXPolicy.allowDeviceMotionDetection = this.allowDeviceMotionDetection;
        pXPolicy.doctorCheckEnabled = this.doctorCheckEnabled;
        pXPolicy.doctorBypassMonitorHeader = getDoctorBypassMonitorHeader();
        return pXPolicy;
    }

    @NotNull
    public final ArrayList<String> domains$PerimeterX_release(@NotNull String appId) {
        Intrinsics.checkNotNullParameter(appId, "appId");
        ArrayList<String> arrayList = this.domains.get(appId);
        return arrayList != null ? arrayList : new ArrayList<>();
    }

    public final boolean getAllowDeviceMotionDetection() {
        return this.allowDeviceMotionDetection;
    }

    public final boolean getAllowTouchDetection() {
        return this.allowTouchDetection;
    }

    public final String getDoctorBypassMonitorHeader() {
        if (Intrinsics.b(this.doctorBypassMonitorHeader, "")) {
            return null;
        }
        return this.doctorBypassMonitorHeader;
    }

    public final boolean getDoctorCheckEnabled() {
        return this.doctorCheckEnabled;
    }

    @NotNull
    public final PXStorageMethod getStorageMethod() {
        return this.storageMethod;
    }

    @NotNull
    public final PXPolicyUrlRequestInterceptionType getUrlRequestInterceptionType() {
        return this.urlRequestInterceptionType;
    }

    public final void setAllowDeviceMotionDetection(boolean z) {
        this.allowDeviceMotionDetection = z;
    }

    public final void setAllowTouchDetection(boolean z) {
        this.allowTouchDetection = z;
    }

    public final void setDoctorBypassMonitorHeader(String str) {
        this.doctorBypassMonitorHeader = str;
    }

    public final void setDoctorCheckEnabled(boolean z) {
        this.doctorCheckEnabled = z;
    }

    public final void setDomains(@NotNull ArrayList<String> domains, @NotNull String appId) {
        Intrinsics.checkNotNullParameter(domains, "domains");
        Intrinsics.checkNotNullParameter(appId, "appId");
        this.domains.put(appId, domains);
    }

    public final void setStorageMethod(@NotNull PXStorageMethod pXStorageMethod) {
        Intrinsics.checkNotNullParameter(pXStorageMethod, "<set-?>");
        this.storageMethod = pXStorageMethod;
    }

    public final void setUrlRequestInterceptionType(@NotNull PXPolicyUrlRequestInterceptionType pXPolicyUrlRequestInterceptionType) {
        Intrinsics.checkNotNullParameter(pXPolicyUrlRequestInterceptionType, "<set-?>");
        this.urlRequestInterceptionType = pXPolicyUrlRequestInterceptionType;
    }

    public PXPolicy(@NotNull PXPolicyUrlRequestInterceptionType urlRequestInterceptionType, @NotNull HashMap<String, ArrayList<String>> domains, @NotNull PXStorageMethod storageMethod, boolean z, boolean z2, String str, boolean z3) {
        Intrinsics.checkNotNullParameter(urlRequestInterceptionType, "urlRequestInterceptionType");
        Intrinsics.checkNotNullParameter(domains, "domains");
        Intrinsics.checkNotNullParameter(storageMethod, "storageMethod");
        this.urlRequestInterceptionType = urlRequestInterceptionType;
        this.domains = domains;
        this.storageMethod = storageMethod;
        this.allowTouchDetection = z;
        this.allowDeviceMotionDetection = z2;
        this.doctorCheckEnabled = z3;
        this.doctorBypassMonitorHeader = str;
    }

    public /* synthetic */ PXPolicy(PXPolicyUrlRequestInterceptionType pXPolicyUrlRequestInterceptionType, HashMap map, PXStorageMethod pXStorageMethod, boolean z, boolean z2, String str, boolean z3, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? PXPolicyUrlRequestInterceptionType.INTERCEPT : pXPolicyUrlRequestInterceptionType, (i & 2) != 0 ? new HashMap() : map, (i & 4) != 0 ? PXStorageMethod.SHARED_PREFERENCES : pXStorageMethod, (i & 8) != 0 ? true : z, (i & 16) != 0 ? true : z2, (i & 32) != 0 ? null : str, (i & 64) != 0 ? false : z3);
    }
}
