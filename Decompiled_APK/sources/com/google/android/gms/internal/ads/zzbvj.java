package com.google.android.gms.internal.ads;

import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.io.IOException;

/* loaded from: classes2.dex */
public final class zzbvj extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzbvj> CREATOR = new C2128h6(13);
    public ParcelFileDescriptor a;
    public Parcelable b = null;

    public zzbvj(ParcelFileDescriptor parcelFileDescriptor) {
        this.a = parcelFileDescriptor;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) throws IOException {
        ParcelFileDescriptor.AutoCloseOutputStream autoCloseOutputStream;
        ParcelFileDescriptor[] parcelFileDescriptorArrCreatePipe;
        if (this.a == null) {
            Parcel parcelObtain = Parcel.obtain();
            try {
                this.b.writeToParcel(parcelObtain, 0);
                byte[] bArrMarshall = parcelObtain.marshall();
                parcelObtain.recycle();
                ParcelFileDescriptor parcelFileDescriptor = null;
                try {
                    parcelFileDescriptorArrCreatePipe = ParcelFileDescriptor.createPipe();
                    autoCloseOutputStream = new ParcelFileDescriptor.AutoCloseOutputStream(parcelFileDescriptorArrCreatePipe[1]);
                } catch (IOException e) {
                    e = e;
                    autoCloseOutputStream = null;
                }
                try {
                    AbstractC2270kd.a.execute(new Qv(11, autoCloseOutputStream, bArrMarshall));
                    parcelFileDescriptor = parcelFileDescriptorArrCreatePipe[0];
                } catch (IOException e2) {
                    e = e2;
                    com.google.android.gms.ads.internal.util.client.i.f("Error transporting the ad response", e);
                    com.google.android.gms.ads.internal.j.C.h.h("LargeParcelTeleporter.pipeData.2", e);
                    com.google.android.gms.common.util.c.d(autoCloseOutputStream);
                    this.a = parcelFileDescriptor;
                    int iN = AbstractC3489l3.n(20293, parcel);
                    AbstractC3489l3.g(parcel, 2, this.a, i);
                    AbstractC3489l3.o(iN, parcel);
                }
                this.a = parcelFileDescriptor;
            } catch (Throwable th) {
                parcelObtain.recycle();
                throw th;
            }
        }
        int iN2 = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.g(parcel, 2, this.a, i);
        AbstractC3489l3.o(iN2, parcel);
    }
}
