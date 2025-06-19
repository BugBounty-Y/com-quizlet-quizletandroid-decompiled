package com.google.android.gms.internal.p000authapi;

import android.graphics.Bitmap;
import android.os.BadParcelableException;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.Parcelable;
import android.support.v4.media.session.a;
import android.util.Log;
import com.android.billingclient.api.t;
import com.google.android.gms.common.data.BitmapTeleporter;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.mlkit_vision_document_scanner.N;
import com.google.android.gms.internal.mlkit_vision_document_scanner.zzry;
import com.google.android.gms.internal.mlkit_vision_document_scanner.zzsa;
import com.google.android.gms.internal.play_billing.AbstractC3791e;
import com.google.android.gms.internal.play_billing.l2;
import com.google.android.gms.internal.play_billing.m2;
import com.google.android.gms.internal.play_billing.n2;
import com.google.android.gms.internal.play_billing.o2;
import com.google.android.play.core.review.c;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

/* loaded from: classes2.dex */
public abstract class g extends Binder implements IInterface {
    public final /* synthetic */ int a;

    public abstract boolean L2(int i, Parcel parcel, Parcel parcel2);

    @Override // android.os.IInterface
    public IBinder asBinder() {
        int i = this.a;
        return this;
    }

    public abstract boolean f3(int i, Parcel parcel, Parcel parcel2);

    @Override // android.os.Binder
    public boolean onTransact(int i, Parcel parcel, Parcel parcel2, int i2) throws IOException {
        switch (this.a) {
            case 0:
                if (i <= 16777215) {
                    parcel.enforceInterface(getInterfaceDescriptor());
                } else if (super.onTransact(i, parcel, parcel2, i2)) {
                    return true;
                }
                return f3(i, parcel, parcel2);
            case 1:
                if (i <= 16777215) {
                    parcel.enforceInterface(getInterfaceDescriptor());
                } else if (super.onTransact(i, parcel, parcel2, i2)) {
                    return true;
                }
                return L2(i, parcel, parcel2);
            case 2:
                if (i <= 16777215) {
                    parcel.enforceInterface(getInterfaceDescriptor());
                } else if (super.onTransact(i, parcel, parcel2, i2)) {
                    return true;
                }
                return p3(i, parcel, parcel2);
            case 3:
            default:
                return super.onTransact(i, parcel, parcel2, i2);
            case 4:
                if (i > 16777215) {
                    if (!super.onTransact(i, parcel, parcel2, i2)) {
                    }
                    return true;
                }
                parcel.enforceInterface(getInterfaceDescriptor());
                if (i == 1) {
                    Parcelable.Creator<zzry> creator = zzry.CREATOR;
                    int i3 = N.a;
                    zzry zzryVar = (zzry) (parcel.readInt() != 0 ? creator.createFromParcel(parcel) : null);
                    int iDataAvail = parcel.dataAvail();
                    if (iDataAvail > 0) {
                        throw new BadParcelableException(a.f(iDataAvail, "Parcel data not fully consumed, unread size: "));
                    }
                    BitmapTeleporter bitmapTeleporter = zzryVar.a;
                    if (!bitmapTeleporter.e) {
                        ParcelFileDescriptor parcelFileDescriptor = bitmapTeleporter.b;
                        u.h(parcelFileDescriptor);
                        DataInputStream dataInputStream = new DataInputStream(new ParcelFileDescriptor.AutoCloseInputStream(parcelFileDescriptor));
                        try {
                            try {
                                byte[] bArr = new byte[dataInputStream.readInt()];
                                int i4 = dataInputStream.readInt();
                                int i5 = dataInputStream.readInt();
                                Bitmap.Config configValueOf = Bitmap.Config.valueOf(dataInputStream.readUTF());
                                dataInputStream.read(bArr);
                                ByteBuffer byteBufferWrap = ByteBuffer.wrap(bArr);
                                Bitmap bitmapCreateBitmap = Bitmap.createBitmap(i4, i5, configValueOf);
                                bitmapCreateBitmap.copyPixelsFromBuffer(byteBufferWrap);
                                bitmapTeleporter.d = bitmapCreateBitmap;
                                bitmapTeleporter.e = true;
                            } catch (IOException e) {
                                throw new IllegalStateException("Could not read from parcel file descriptor", e);
                            }
                        } finally {
                            try {
                                dataInputStream.close();
                            } catch (IOException e2) {
                                Log.w("BitmapTeleporter", "Could not close stream", e2);
                            }
                        }
                    }
                } else {
                    if (i != 2) {
                        return false;
                    }
                    Parcelable.Creator<zzsa> creator2 = zzsa.CREATOR;
                    int i6 = N.a;
                    int iDataAvail2 = parcel.dataAvail();
                    if (iDataAvail2 > 0) {
                        throw new BadParcelableException(a.f(iDataAvail2, "Parcel data not fully consumed, unread size: "));
                    }
                    parcel2.writeNoException();
                    parcel2.writeInt(0);
                }
                return true;
            case 5:
                if (i > 16777215) {
                    if (!super.onTransact(i, parcel, parcel2, i2)) {
                    }
                    return true;
                }
                parcel.enforceInterface(getInterfaceDescriptor());
                t tVar = (t) this;
                if (i != 1) {
                    return false;
                }
                int i7 = parcel.readInt();
                int i8 = AbstractC3791e.a;
                int iDataAvail3 = parcel.dataAvail();
                if (iDataAvail3 > 0) {
                    throw new BadParcelableException(a.f(iDataAvail3, "Parcel data not fully consumed, unread size: "));
                }
                Integer numValueOf = Integer.valueOf(i7);
                m2 m2Var = tVar.b;
                m2Var.d = true;
                o2 o2Var = m2Var.b;
                if (o2Var != null) {
                    n2 n2Var = o2Var.b;
                    n2Var.getClass();
                    if (l2.f.w(n2Var, null, numValueOf)) {
                        l2.d(n2Var);
                        m2Var.a = null;
                        m2Var.b = null;
                        m2Var.c = null;
                    }
                }
                return true;
            case 6:
                if (i > 16777215) {
                    if (!super.onTransact(i, parcel, parcel2, i2)) {
                    }
                    return true;
                }
                parcel.enforceInterface(getInterfaceDescriptor());
                c cVar = (c) this;
                if (i != 2) {
                    return false;
                }
                Parcelable.Creator creator3 = Bundle.CREATOR;
                int i9 = com.google.android.play.core.review.internal.a.a;
                Bundle bundle = (Bundle) (parcel.readInt() != 0 ? (Parcelable) creator3.createFromParcel(parcel) : null);
                int iDataAvail4 = parcel.dataAvail();
                if (iDataAvail4 > 0) {
                    throw new BadParcelableException(a.f(iDataAvail4, "Parcel data not fully consumed, unread size: "));
                }
                cVar.v3(bundle);
                return true;
        }
    }

    public boolean p3(int i, Parcel parcel, Parcel parcel2) {
        return false;
    }

    public g(String str, int i) {
        this.a = i;
        switch (i) {
            case 1:
                attachInterface(this, str);
                break;
            case 2:
                attachInterface(this, str);
                break;
            default:
                attachInterface(this, str);
                break;
        }
    }
}
