package com.google.android.gms.fido.fido2;

import android.app.PendingIntent;
import android.os.BadParcelableException;
import android.os.Binder;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.appset.zzc;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.internal.fido.AbstractC2946j;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3465h3;
import com.google.android.gms.tasks.f;

/* loaded from: classes2.dex */
public final class b extends Binder implements IInterface {
    public final /* synthetic */ int a;
    public final /* synthetic */ f b;

    public b(f fVar, int i) {
        this.a = i;
        switch (i) {
            case 1:
                this.b = fVar;
                attachInterface(this, "com.google.android.gms.appset.internal.IAppSetIdCallback");
                break;
            default:
                this.b = fVar;
                attachInterface(this, "com.google.android.gms.fido.fido2.internal.regular.IFido2AppCallbacks");
                break;
        }
    }

    @Override // android.os.IInterface
    public final IBinder asBinder() {
        int i = this.a;
        return this;
    }

    @Override // android.os.Binder
    public final boolean onTransact(int i, Parcel parcel, Parcel parcel2, int i2) {
        switch (this.a) {
            case 0:
                if (i > 16777215) {
                    if (!super.onTransact(i, parcel, parcel2, i2)) {
                    }
                    return true;
                }
                parcel.enforceInterface(getInterfaceDescriptor());
                if (i != 1) {
                    return false;
                }
                Parcelable.Creator<Status> creator = Status.CREATOR;
                int i3 = AbstractC2946j.a;
                Status statusCreateFromParcel = parcel.readInt() == 0 ? null : creator.createFromParcel(parcel);
                PendingIntent pendingIntent = (PendingIntent) (parcel.readInt() != 0 ? (Parcelable) PendingIntent.CREATOR.createFromParcel(parcel) : null);
                int iDataAvail = parcel.dataAvail();
                if (iDataAvail > 0) {
                    throw new BadParcelableException(android.support.v4.media.session.a.f(iDataAvail, "Parcel data not fully consumed, unread size: "));
                }
                AbstractC3465h3.c(statusCreateFromParcel, pendingIntent, this.b);
                return true;
            default:
                if (i > 16777215) {
                    if (!super.onTransact(i, parcel, parcel2, i2)) {
                    }
                    return true;
                }
                parcel.enforceInterface(getInterfaceDescriptor());
                if (i != 1) {
                    return false;
                }
                Parcelable.Creator<Status> creator2 = Status.CREATOR;
                int i4 = com.google.android.gms.internal.appset.a.a;
                Status statusCreateFromParcel2 = parcel.readInt() == 0 ? null : creator2.createFromParcel(parcel);
                zzc zzcVarCreateFromParcel = parcel.readInt() == 0 ? null : zzc.CREATOR.createFromParcel(parcel);
                AbstractC3465h3.c(statusCreateFromParcel2, zzcVarCreateFromParcel != null ? new com.google.android.gms.appset.b(zzcVarCreateFromParcel.a, zzcVarCreateFromParcel.b) : null, this.b);
                return true;
        }
    }
}
