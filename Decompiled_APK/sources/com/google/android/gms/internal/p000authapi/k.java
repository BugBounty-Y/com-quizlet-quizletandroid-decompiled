package com.google.android.gms.internal.p000authapi;

import android.content.Context;
import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Looper;
import androidx.camera.camera2.internal.c0;
import com.google.android.gms.common.Feature;
import com.google.android.gms.common.api.internal.n;
import com.google.android.gms.common.internal.AbstractC1656f;

/* loaded from: classes2.dex */
public final class k extends AbstractC1656f {
    public final Bundle A;

    public k(Context context, Looper looper, c0 c0Var, n nVar, n nVar2) {
        super(context, looper, 223, c0Var, nVar, nVar2);
        this.A = new Bundle();
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e, com.google.android.gms.common.api.c
    public final int a() {
        return 17895000;
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final IInterface d(IBinder iBinder) {
        if (iBinder == null) {
            return null;
        }
        IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.auth.api.identity.internal.ICredentialSavingService");
        return iInterfaceQueryLocalInterface instanceof l ? (l) iInterfaceQueryLocalInterface : new l(iBinder, "com.google.android.gms.auth.api.identity.internal.ICredentialSavingService", 1);
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final Feature[] h() {
        return e.d;
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final Bundle j() {
        return this.A;
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final String n() {
        return "com.google.android.gms.auth.api.identity.internal.ICredentialSavingService";
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final String o() {
        return "com.google.android.gms.auth.api.identity.service.credentialsaving.START";
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final boolean p() {
        return true;
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final boolean s() {
        return true;
    }
}
