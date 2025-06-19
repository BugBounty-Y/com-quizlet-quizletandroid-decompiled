package com.google.android.gms.measurement.internal;

import android.os.Parcel;
import com.google.android.gms.internal.measurement.AbstractBinderC3076x;
import com.google.android.gms.internal.measurement.AbstractC3081y;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class S0 extends AbstractBinderC3076x implements InterfaceC3905z {
    public final /* synthetic */ AtomicReference a;
    public final /* synthetic */ Y0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public S0(Y0 y0, AtomicReference atomicReference) {
        super("com.google.android.gms.measurement.internal.IUploadBatchesCallback");
        this.a = atomicReference;
        this.b = y0;
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3905z
    public final void S1(zzpe zzpeVar) {
        AtomicReference atomicReference = this.a;
        synchronized (atomicReference) {
            I i = ((Y) this.b.b).i;
            Y.k(i);
            i.o.g("[sgtm] Got upload batches from service. count", Integer.valueOf(zzpeVar.a.size()));
            atomicReference.set(zzpeVar);
            atomicReference.notifyAll();
        }
    }

    @Override // com.google.android.gms.internal.measurement.AbstractBinderC3076x
    public final boolean V(int i, Parcel parcel, Parcel parcel2) {
        if (i != 2) {
            return false;
        }
        zzpe zzpeVar = (zzpe) AbstractC3081y.a(parcel, zzpe.CREATOR);
        AbstractC3081y.b(parcel);
        S1(zzpeVar);
        return true;
    }
}
