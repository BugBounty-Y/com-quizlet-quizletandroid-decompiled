package com.google.android.gms.measurement.internal;

import android.os.Parcel;
import com.google.android.gms.internal.measurement.AbstractBinderC3076x;
import com.google.android.gms.internal.measurement.AbstractC3081y;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class R0 extends AbstractBinderC3076x implements InterfaceC3901x {
    public final /* synthetic */ AtomicReference a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public R0(AtomicReference atomicReference) {
        super("com.google.android.gms.measurement.internal.ITriggerUrisCallback");
        this.a = atomicReference;
    }

    @Override // com.google.android.gms.internal.measurement.AbstractBinderC3076x
    public final boolean V(int i, Parcel parcel, Parcel parcel2) {
        if (i != 2) {
            return false;
        }
        ArrayList arrayListCreateTypedArrayList = parcel.createTypedArrayList(zzov.CREATOR);
        AbstractC3081y.b(parcel);
        w3(arrayListCreateTypedArrayList);
        return true;
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3901x
    public final void w3(List list) {
        AtomicReference atomicReference = this.a;
        synchronized (atomicReference) {
            atomicReference.set(list);
            atomicReference.notifyAll();
        }
    }
}
