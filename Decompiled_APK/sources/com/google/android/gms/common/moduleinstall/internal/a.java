package com.google.android.gms.common.moduleinstall.internal;

import android.os.IInterface;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.moduleinstall.ModuleAvailabilityResponse;
import com.google.android.gms.common.moduleinstall.ModuleInstallResponse;

/* loaded from: classes2.dex */
public interface a extends IInterface {
    void G1(Status status, ModuleInstallResponse moduleInstallResponse);

    void V0(Status status, ModuleAvailabilityResponse moduleAvailabilityResponse);
}
