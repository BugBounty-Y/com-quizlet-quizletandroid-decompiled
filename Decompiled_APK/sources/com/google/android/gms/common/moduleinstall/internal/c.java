package com.google.android.gms.common.moduleinstall.internal;

import android.os.Parcel;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.moduleinstall.ModuleAvailabilityResponse;
import com.google.android.gms.common.moduleinstall.ModuleInstallResponse;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3465h3;
import com.google.android.gms.internal.p000authapi.g;
import com.google.android.gms.tasks.f;

/* loaded from: classes2.dex */
public final class c extends g implements a {
    public final /* synthetic */ int b;
    public final /* synthetic */ f c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(f fVar, int i) {
        super("com.google.android.gms.common.moduleinstall.internal.IModuleInstallCallbacks", 1);
        this.b = i;
        this.c = fVar;
    }

    @Override // com.google.android.gms.common.moduleinstall.internal.a
    public void G1(Status status, ModuleInstallResponse moduleInstallResponse) {
        switch (this.b) {
            case 1:
                AbstractC3465h3.d(status, moduleInstallResponse, this.c);
                return;
            default:
                throw new UnsupportedOperationException();
        }
    }

    @Override // com.google.android.gms.internal.p000authapi.g
    public final boolean L2(int i, Parcel parcel, Parcel parcel2) {
        if (i == 1) {
            Status status = (Status) com.google.android.gms.internal.base.a.a(parcel, Status.CREATOR);
            ModuleAvailabilityResponse moduleAvailabilityResponse = (ModuleAvailabilityResponse) com.google.android.gms.internal.base.a.a(parcel, ModuleAvailabilityResponse.CREATOR);
            com.google.android.gms.internal.base.a.d(parcel);
            V0(status, moduleAvailabilityResponse);
            return true;
        }
        if (i == 2) {
            Status status2 = (Status) com.google.android.gms.internal.base.a.a(parcel, Status.CREATOR);
            ModuleInstallResponse moduleInstallResponse = (ModuleInstallResponse) com.google.android.gms.internal.base.a.a(parcel, ModuleInstallResponse.CREATOR);
            com.google.android.gms.internal.base.a.d(parcel);
            G1(status2, moduleInstallResponse);
            return true;
        }
        if (i == 3) {
            com.google.android.gms.internal.base.a.d(parcel);
            throw new UnsupportedOperationException();
        }
        if (i != 4) {
            return false;
        }
        com.google.android.gms.internal.base.a.d(parcel);
        throw new UnsupportedOperationException();
    }

    @Override // com.google.android.gms.common.moduleinstall.internal.a
    public void V0(Status status, ModuleAvailabilityResponse moduleAvailabilityResponse) {
        switch (this.b) {
            case 0:
                AbstractC3465h3.d(status, moduleAvailabilityResponse, this.c);
                return;
            default:
                throw new UnsupportedOperationException();
        }
    }
}
