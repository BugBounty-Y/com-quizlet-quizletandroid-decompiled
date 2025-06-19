package com.google.android.gms.signin.internal;

import android.content.Context;
import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Looper;
import androidx.camera.camera2.internal.c0;
import com.google.android.gms.common.api.f;
import com.google.android.gms.common.api.g;
import com.google.android.gms.common.internal.AbstractC1656f;

/* loaded from: classes2.dex */
public final class a extends AbstractC1656f implements com.google.android.gms.common.api.c {
    public final boolean A;
    public final c0 B;
    public final Bundle C;
    public final Integer D;

    public a(Context context, Looper looper, c0 c0Var, Bundle bundle, f fVar, g gVar) {
        super(context, looper, 44, c0Var, fVar, gVar);
        this.A = true;
        this.B = c0Var;
        this.C = bundle;
        this.D = (Integer) c0Var.g;
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e, com.google.android.gms.common.api.c
    public final int a() {
        return 12451000;
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e, com.google.android.gms.common.api.c
    public final boolean b() {
        return this.A;
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final IInterface d(IBinder iBinder) {
        if (iBinder == null) {
            return null;
        }
        IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.signin.internal.ISignInService");
        return iInterfaceQueryLocalInterface instanceof c ? (c) iInterfaceQueryLocalInterface : new c(iBinder, "com.google.android.gms.signin.internal.ISignInService", 2);
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final Bundle j() {
        c0 c0Var = this.B;
        boolean zEquals = this.c.getPackageName().equals((String) c0Var.d);
        Bundle bundle = this.C;
        if (!zEquals) {
            bundle.putString("com.google.android.gms.signin.internal.realClientPackageName", (String) c0Var.d);
        }
        return bundle;
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final String n() {
        return "com.google.android.gms.signin.internal.ISignInService";
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final String o() {
        return "com.google.android.gms.signin.service.START";
    }
}
