package com.google.android.gms.internal.ads;

import android.os.RemoteException;
import com.google.android.gms.ads.nativead.NativeCustomFormatAd;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.tb, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2654tb implements NativeCustomFormatAd {
    public final J8 a;
    public L9 b;

    public C2654tb(J8 j8) {
        this.a = j8;
    }

    @Override // com.google.android.gms.ads.nativead.NativeCustomFormatAd
    public final void destroy() {
        try {
            this.a.k();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
        }
    }

    @Override // com.google.android.gms.ads.nativead.NativeCustomFormatAd
    public final List getAvailableAssetNames() {
        try {
            return this.a.n();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
            return null;
        }
    }

    @Override // com.google.android.gms.ads.nativead.NativeCustomFormatAd
    public final String getCustomFormatId() {
        try {
            return this.a.zzi();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
            return null;
        }
    }

    @Override // com.google.android.gms.ads.nativead.NativeCustomFormatAd
    public final com.google.android.gms.ads.nativead.e getDisplayOpenMeasurement() {
        try {
            if (this.b == null) {
                J8 j8 = this.a;
                if (j8.p()) {
                    L9 l9 = new L9(12);
                    try {
                        j8.l();
                    } catch (RemoteException e) {
                        com.google.android.gms.ads.internal.util.client.i.f("", e);
                    }
                    this.b = l9;
                }
            }
        } catch (RemoteException e2) {
            com.google.android.gms.ads.internal.util.client.i.f("", e2);
        }
        return this.b;
    }

    @Override // com.google.android.gms.ads.nativead.NativeCustomFormatAd
    public final com.google.android.gms.ads.nativead.c getImage(String str) {
        try {
            InterfaceC2860y8 interfaceC2860y8Z = this.a.Z(str);
            if (interfaceC2860y8Z != null) {
                return new C2568rb(interfaceC2860y8Z);
            }
            return null;
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
            return null;
        }
    }

    @Override // com.google.android.gms.ads.nativead.NativeCustomFormatAd
    public final com.google.android.gms.ads.m getMediaContent() {
        try {
            J8 j8 = this.a;
            if (j8.f() != null) {
                return new com.google.android.gms.ads.internal.client.F0(j8.f(), j8);
            }
            return null;
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
            return null;
        }
    }

    @Override // com.google.android.gms.ads.nativead.NativeCustomFormatAd
    public final CharSequence getText(String str) {
        try {
            return this.a.r3(str);
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
            return null;
        }
    }

    @Override // com.google.android.gms.ads.nativead.NativeCustomFormatAd
    public final void performClick(String str) {
        try {
            this.a.T(str);
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
        }
    }

    @Override // com.google.android.gms.ads.nativead.NativeCustomFormatAd
    public final void recordImpression() {
        try {
            this.a.v();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
        }
    }
}
