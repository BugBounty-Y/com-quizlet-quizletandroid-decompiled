package com.google.android.gms.internal.p000authapi;

import android.os.Parcel;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.internal.InterfaceC1648f;
import com.google.android.gms.internal.base.a;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3465h3;
import com.google.android.gms.tasks.f;

/* loaded from: classes2.dex */
public final class c extends g implements InterfaceC1648f {
    public final /* synthetic */ f b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(f fVar) {
        super("com.google.android.gms.common.api.internal.IStatusCallback", 1);
        this.b = fVar;
    }

    @Override // com.google.android.gms.internal.p000authapi.g
    public final boolean L2(int i, Parcel parcel, Parcel parcel2) {
        if (i != 1) {
            return false;
        }
        Status status = (Status) a.a(parcel, Status.CREATOR);
        a.d(parcel);
        l1(status);
        return true;
    }

    @Override // com.google.android.gms.common.api.internal.InterfaceC1648f
    public final void l1(Status status) {
        AbstractC3465h3.c(status, null, this.b);
    }
}
