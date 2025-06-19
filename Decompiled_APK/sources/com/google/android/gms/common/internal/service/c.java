package com.google.android.gms.common.internal.service;

import android.content.Context;
import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Looper;
import androidx.camera.camera2.internal.c0;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.common.Feature;
import com.google.android.gms.common.api.internal.n;
import com.google.android.gms.common.internal.AbstractC1656f;
import com.google.android.gms.common.internal.k;

/* loaded from: classes2.dex */
public final class c extends AbstractC1656f {
    public final k A;

    public c(Context context, Looper looper, c0 c0Var, k kVar, n nVar, n nVar2) {
        super(context, looper, SubsamplingScaleImageView.ORIENTATION_270, c0Var, nVar, nVar2);
        this.A = kVar;
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e, com.google.android.gms.common.api.c
    public final int a() {
        return 203400000;
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final IInterface d(IBinder iBinder) {
        if (iBinder == null) {
            return null;
        }
        IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.common.internal.service.IClientTelemetryService");
        return iInterfaceQueryLocalInterface instanceof a ? (a) iInterfaceQueryLocalInterface : new a(iBinder, "com.google.android.gms.common.internal.service.IClientTelemetryService", 2);
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final Feature[] h() {
        return com.google.android.gms.internal.base.b.b;
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final Bundle j() {
        k kVar = this.A;
        kVar.getClass();
        Bundle bundle = new Bundle();
        String str = kVar.a;
        if (str != null) {
            bundle.putString("api", str);
        }
        return bundle;
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final String n() {
        return "com.google.android.gms.common.internal.service.IClientTelemetryService";
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final String o() {
        return "com.google.android.gms.common.telemetry.service.START";
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final boolean p() {
        return true;
    }
}
