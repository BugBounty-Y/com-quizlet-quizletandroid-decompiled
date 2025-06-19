package com.google.android.gms.internal.measurement;

import android.os.Bundle;
import android.os.Parcel;
import com.google.android.gms.measurement.internal.InterfaceC3885o0;
import com.google.android.gms.measurement.internal.InterfaceC3887p0;

/* renamed from: com.google.android.gms.internal.measurement.g0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC2993g0 extends AbstractBinderC3076x implements P {
    public final /* synthetic */ int a;
    public final Object b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BinderC2993g0(Object obj, int i) {
        super("com.google.android.gms.measurement.api.internal.IEventHandlerProxy");
        this.a = i;
        this.b = obj;
    }

    @Override // com.google.android.gms.internal.measurement.P
    public final void H3(String str, String str2, Bundle bundle, long j) {
        switch (this.a) {
            case 0:
                ((InterfaceC3885o0) this.b).interceptEvent(str, str2, bundle, j);
                break;
            default:
                ((InterfaceC3887p0) this.b).onEvent(str, str2, bundle, j);
                break;
        }
    }

    @Override // com.google.android.gms.internal.measurement.AbstractBinderC3076x
    public final boolean V(int i, Parcel parcel, Parcel parcel2) {
        if (i != 1) {
            if (i != 2) {
                return false;
            }
            int iZze = zze();
            parcel2.writeNoException();
            parcel2.writeInt(iZze);
            return true;
        }
        String string = parcel.readString();
        String string2 = parcel.readString();
        Bundle bundle = (Bundle) AbstractC3081y.a(parcel, Bundle.CREATOR);
        long j = parcel.readLong();
        AbstractC3081y.b(parcel);
        H3(string, string2, bundle, j);
        parcel2.writeNoException();
        return true;
    }

    @Override // com.google.android.gms.internal.measurement.P
    public final int zze() {
        switch (this.a) {
            case 0:
                return System.identityHashCode((InterfaceC3885o0) this.b);
            default:
                return System.identityHashCode((InterfaceC3887p0) this.b);
        }
    }
}
