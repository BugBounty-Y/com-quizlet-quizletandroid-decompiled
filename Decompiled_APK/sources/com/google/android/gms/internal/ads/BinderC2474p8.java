package com.google.android.gms.internal.ads;

import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;

/* renamed from: com.google.android.gms.internal.ads.p8, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC2474p8 extends AbstractBinderC2814x5 implements InterfaceC2860y8 {
    public final Drawable a;
    public final Uri b;
    public final double c;
    public final int d;
    public final int e;

    public BinderC2474p8(Drawable drawable, Uri uri, double d, int i, int i2) {
        super("com.google.android.gms.ads.internal.formats.client.INativeAdImage");
        this.a = drawable;
        this.b = uri;
        this.c = d;
        this.d = i;
        this.e = i2;
    }

    public static InterfaceC2860y8 e4(IBinder iBinder) {
        if (iBinder == null) {
            return null;
        }
        IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.ads.internal.formats.client.INativeAdImage");
        return iInterfaceQueryLocalInterface instanceof InterfaceC2860y8 ? (InterfaceC2860y8) iInterfaceQueryLocalInterface : new C2817x8(iBinder);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2860y8
    public final int a() {
        return this.e;
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        if (i == 1) {
            com.google.android.gms.dynamic.a aVarF = f();
            parcel2.writeNoException();
            AbstractC2857y5.e(parcel2, aVarF);
            return true;
        }
        if (i == 2) {
            parcel2.writeNoException();
            AbstractC2857y5.d(parcel2, this.b);
            return true;
        }
        if (i == 3) {
            parcel2.writeNoException();
            parcel2.writeDouble(this.c);
            return true;
        }
        if (i == 4) {
            parcel2.writeNoException();
            parcel2.writeInt(this.d);
            return true;
        }
        if (i != 5) {
            return false;
        }
        parcel2.writeNoException();
        parcel2.writeInt(this.e);
        return true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2860y8
    public final com.google.android.gms.dynamic.a f() {
        return new com.google.android.gms.dynamic.b(this.a);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2860y8
    public final int j() {
        return this.d;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2860y8
    public final double zzb() {
        return this.c;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2860y8
    public final Uri zze() {
        return this.b;
    }
}
