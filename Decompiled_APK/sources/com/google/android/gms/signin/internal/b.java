package com.google.android.gms.signin.internal;

import android.os.Parcel;
import androidx.camera.core.impl.utils.futures.h;
import com.google.android.gms.common.api.internal.x;
import com.google.android.gms.internal.p000authapi.g;

/* loaded from: classes2.dex */
public abstract class b extends g {
    @Override // com.google.android.gms.internal.p000authapi.g
    public final boolean L2(int i, Parcel parcel, Parcel parcel2) {
        switch (i) {
            case 3:
                com.google.android.gms.internal.base.a.d(parcel);
                break;
            case 4:
                com.google.android.gms.internal.base.a.d(parcel);
                break;
            case 5:
            default:
                return false;
            case 6:
                com.google.android.gms.internal.base.a.d(parcel);
                break;
            case 7:
                com.google.android.gms.internal.base.a.d(parcel);
                break;
            case 8:
                zak zakVar = (zak) com.google.android.gms.internal.base.a.a(parcel, zak.CREATOR);
                com.google.android.gms.internal.base.a.d(parcel);
                x xVar = (x) this;
                xVar.c.post(new h(xVar, false, zakVar, 22));
                break;
            case 9:
                com.google.android.gms.internal.base.a.d(parcel);
                break;
        }
        parcel2.writeNoException();
        return true;
    }
}
