package com.google.android.gms.internal.ads;

import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.RemoteException;

/* renamed from: com.google.android.gms.internal.ads.z8, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2903z8 {
    public final InterfaceC2860y8 a;
    public final Drawable b;
    public final Uri c;
    public final double d;
    public final int e;
    public final int f;

    public C2903z8(InterfaceC2860y8 interfaceC2860y8) {
        double dZzb;
        int iJ;
        com.google.android.gms.dynamic.a aVarF;
        this.a = interfaceC2860y8;
        Uri uriZze = null;
        try {
            aVarF = interfaceC2860y8.f();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
        }
        Drawable drawable = aVarF != null ? (Drawable) com.google.android.gms.dynamic.b.I3(aVarF) : null;
        this.b = drawable;
        try {
            uriZze = this.a.zze();
        } catch (RemoteException e2) {
            com.google.android.gms.ads.internal.util.client.i.f("", e2);
        }
        this.c = uriZze;
        try {
            dZzb = this.a.zzb();
        } catch (RemoteException e3) {
            com.google.android.gms.ads.internal.util.client.i.f("", e3);
            dZzb = 1.0d;
        }
        this.d = dZzb;
        int iA = -1;
        try {
            iJ = this.a.j();
        } catch (RemoteException e4) {
            com.google.android.gms.ads.internal.util.client.i.f("", e4);
            iJ = -1;
        }
        this.e = iJ;
        try {
            iA = this.a.a();
        } catch (RemoteException e5) {
            com.google.android.gms.ads.internal.util.client.i.f("", e5);
        }
        this.f = iA;
    }
}
