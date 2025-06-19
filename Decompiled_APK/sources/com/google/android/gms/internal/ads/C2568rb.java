package com.google.android.gms.internal.ads;

import android.graphics.drawable.Drawable;
import android.os.RemoteException;

/* renamed from: com.google.android.gms.internal.ads.rb, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2568rb extends com.google.android.gms.ads.nativead.c {
    public final InterfaceC2860y8 a;
    public final Drawable b;

    public C2568rb(InterfaceC2860y8 interfaceC2860y8) {
        this.a = interfaceC2860y8;
        Drawable drawable = null;
        try {
            com.google.android.gms.dynamic.a aVarF = interfaceC2860y8.f();
            if (aVarF != null) {
                drawable = (Drawable) com.google.android.gms.dynamic.b.I3(aVarF);
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
        }
        this.b = drawable;
        try {
            this.a.zze();
        } catch (RemoteException e2) {
            com.google.android.gms.ads.internal.util.client.i.f("", e2);
        }
        try {
            this.a.zzb();
        } catch (RemoteException e3) {
            com.google.android.gms.ads.internal.util.client.i.f("", e3);
        }
        try {
            this.a.j();
        } catch (RemoteException e4) {
            com.google.android.gms.ads.internal.util.client.i.f("", e4);
        }
        try {
            this.a.a();
        } catch (RemoteException e5) {
            com.google.android.gms.ads.internal.util.client.i.f("", e5);
        }
    }
}
