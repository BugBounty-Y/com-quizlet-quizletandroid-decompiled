package com.google.android.gms.internal.appset;

import android.os.IBinder;
import android.os.IInterface;
import com.google.android.gms.common.Feature;
import com.google.android.gms.common.internal.AbstractC1656f;

/* loaded from: classes2.dex */
public final class b extends AbstractC1656f {
    @Override // com.google.android.gms.common.internal.AbstractC1655e, com.google.android.gms.common.api.c
    public final int a() {
        return 212800000;
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final /* synthetic */ IInterface d(IBinder iBinder) {
        if (iBinder == null) {
            return null;
        }
        IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.appset.internal.IAppSetService");
        return iInterfaceQueryLocalInterface instanceof c ? (c) iInterfaceQueryLocalInterface : new c(iBinder);
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final Feature[] h() {
        return com.google.android.gms.appset.c.b;
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final String n() {
        return "com.google.android.gms.appset.internal.IAppSetService";
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final String o() {
        return "com.google.android.gms.appset.service.START";
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
