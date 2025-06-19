package com.google.android.gms.internal.p000authapi;

import android.content.Context;
import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Looper;
import androidx.camera.camera2.internal.c0;
import androidx.work.impl.model.l;
import com.google.android.gms.auth.api.c;
import com.google.android.gms.common.api.internal.n;
import com.google.android.gms.common.internal.AbstractC1656f;

/* loaded from: classes2.dex */
public final class i extends AbstractC1656f {
    public final c A;

    public i(Context context, Looper looper, c0 c0Var, c cVar, n nVar, n nVar2) {
        super(context, looper, 68, c0Var, nVar, nVar2);
        cVar = cVar == null ? c.c : cVar;
        l lVar = new l(9);
        lVar.b = Boolean.FALSE;
        c cVar2 = c.c;
        cVar.getClass();
        lVar.b = Boolean.valueOf(cVar.a);
        lVar.c = cVar.b;
        lVar.c = f.a();
        this.A = new c(lVar);
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e, com.google.android.gms.common.api.c
    public final int a() {
        return 12800000;
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final IInterface d(IBinder iBinder) {
        if (iBinder == null) {
            return null;
        }
        IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.auth.api.credentials.internal.ICredentialsService");
        return iInterfaceQueryLocalInterface instanceof j ? (j) iInterfaceQueryLocalInterface : new j(iBinder, "com.google.android.gms.auth.api.credentials.internal.ICredentialsService", 1);
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final Bundle j() {
        c cVar = this.A;
        cVar.getClass();
        Bundle bundle = new Bundle();
        bundle.putString("consumer_package", null);
        bundle.putBoolean("force_save_dialog", cVar.a);
        bundle.putString("log_session_id", cVar.b);
        return bundle;
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final String n() {
        return "com.google.android.gms.auth.api.credentials.internal.ICredentialsService";
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final String o() {
        return "com.google.android.gms.auth.api.credentials.service.START";
    }
}
