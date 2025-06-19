package com.google.android.gms.internal.ads;

import android.os.Parcel;

/* loaded from: classes2.dex */
public final class I5 extends AbstractBinderC2814x5 implements com.google.android.gms.ads.internal.client.P {
    public static final /* synthetic */ int b = 0;
    public final com.google.android.gms.ads.admanager.a a;

    public I5(com.google.android.gms.ads.admanager.a aVar) {
        super("com.google.android.gms.ads.internal.client.IAppEventListener");
        this.a = aVar;
    }

    @Override // com.google.android.gms.ads.internal.client.P
    public final void b3(String str, String str2) {
        this.a.onAppEvent(str, str2);
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        if (i != 1) {
            return false;
        }
        String string = parcel.readString();
        String string2 = parcel.readString();
        AbstractC2857y5.b(parcel);
        b3(string, string2);
        parcel2.writeNoException();
        return true;
    }
}
