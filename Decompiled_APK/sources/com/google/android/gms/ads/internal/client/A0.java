package com.google.android.gms.ads.internal.client;

import android.content.Context;
import android.content.res.TypedArray;
import android.os.RemoteException;
import android.text.TextUtils;
import android.util.AttributeSet;
import com.google.android.gms.internal.ads.BinderC2739va;
import com.google.android.gms.internal.ads.I5;
import com.google.android.gms.internal.mlkit_vision_common.T2;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes2.dex */
public final class A0 {
    public final BinderC2739va a;
    public final R0 b;
    public final AtomicBoolean c;
    public final com.google.android.gms.ads.s d;
    public final z0 e;
    public InterfaceC1582a f;
    public com.google.android.gms.ads.d g;
    public com.google.android.gms.ads.h[] h;
    public com.google.android.gms.ads.admanager.a i;
    public K j;
    public com.google.android.gms.ads.t k;
    public String l;
    public final com.google.android.gms.ads.k m;
    public boolean n;

    public A0(com.google.android.gms.ads.k kVar, AttributeSet attributeSet, boolean z) {
        com.google.android.gms.ads.h[] hVarArrC;
        zzr zzrVar;
        R0 r0 = R0.a;
        this.a = new BinderC2739va();
        this.d = new com.google.android.gms.ads.s();
        this.e = new z0(this);
        this.m = kVar;
        this.b = r0;
        this.j = null;
        this.c = new AtomicBoolean(false);
        if (attributeSet != null) {
            Context context = kVar.getContext();
            try {
                TypedArray typedArrayObtainAttributes = context.getResources().obtainAttributes(attributeSet, com.google.android.gms.ads.o.a);
                String string = typedArrayObtainAttributes.getString(0);
                String string2 = typedArrayObtainAttributes.getString(1);
                boolean zIsEmpty = TextUtils.isEmpty(string);
                boolean zIsEmpty2 = TextUtils.isEmpty(string2);
                if (!zIsEmpty && zIsEmpty2) {
                    hVarArrC = T2.c(string);
                } else {
                    if (!zIsEmpty || zIsEmpty2) {
                        if (zIsEmpty) {
                            typedArrayObtainAttributes.recycle();
                            throw new IllegalArgumentException("Required XML attribute \"adSize\" was missing.");
                        }
                        typedArrayObtainAttributes.recycle();
                        throw new IllegalArgumentException("Either XML attribute \"adSize\" or XML attribute \"supportedAdSizes\" should be specified, but not both.");
                    }
                    hVarArrC = T2.c(string2);
                }
                String string3 = typedArrayObtainAttributes.getString(2);
                typedArrayObtainAttributes.recycle();
                if (TextUtils.isEmpty(string3)) {
                    throw new IllegalArgumentException("Required XML attribute \"adUnitId\" was missing.");
                }
                if (!z && hVarArrC.length != 1) {
                    throw new IllegalArgumentException("The adSizes XML attribute is only allowed on PublisherAdViews.");
                }
                this.h = hVarArrC;
                this.l = string3;
                if (kVar.isInEditMode()) {
                    com.google.android.gms.ads.internal.util.client.c cVar = C1614q.f.a;
                    com.google.android.gms.ads.h hVar = this.h[0];
                    if (hVar.equals(com.google.android.gms.ads.h.q)) {
                        zzrVar = new zzr("invalid", 0, 0, false, 0, 0, null, false, false, false, true, false, false, false, false);
                    } else {
                        zzrVar = new zzr(context, hVar);
                        zzrVar.j = false;
                    }
                    cVar.getClass();
                    com.google.android.gms.ads.internal.util.client.c.e(kVar, zzrVar, "Ads by Google", -16777216, -1);
                }
            } catch (IllegalArgumentException e) {
                com.google.android.gms.ads.internal.util.client.c cVar2 = C1614q.f.a;
                zzr zzrVar2 = new zzr(context, com.google.android.gms.ads.h.i);
                String message = e.getMessage();
                String message2 = e.getMessage();
                cVar2.getClass();
                if (message2 != null) {
                    com.google.android.gms.ads.internal.util.client.i.h(message2);
                }
                com.google.android.gms.ads.internal.util.client.c.e(kVar, zzrVar2, message, -65536, -16777216);
            }
        }
    }

    public static zzr a(Context context, com.google.android.gms.ads.h[] hVarArr) {
        for (com.google.android.gms.ads.h hVar : hVarArr) {
            if (hVar.equals(com.google.android.gms.ads.h.q)) {
                return new zzr("invalid", 0, 0, false, 0, 0, null, false, false, false, true, false, false, false, false);
            }
        }
        zzr zzrVar = new zzr(context, hVarArr);
        zzrVar.j = false;
        return zzrVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x00d3 A[Catch: RemoteException -> 0x00d1, TRY_LEAVE, TryCatch #0 {RemoteException -> 0x00d1, blocks: (B:28:0x009e, B:30:0x00a4, B:32:0x00b2, B:34:0x00c4, B:37:0x00d3), top: B:51:0x009e, outer: #1 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(com.google.android.gms.ads.internal.client.y0 r13) {
        /*
            Method dump skipped, instructions count: 262
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.ads.internal.client.A0.b(com.google.android.gms.ads.internal.client.y0):void");
    }

    public final void c(InterfaceC1582a interfaceC1582a) {
        try {
            this.f = interfaceC1582a;
            K k = this.j;
            if (k != null) {
                k.A3(interfaceC1582a != null ? new BinderC1610o(interfaceC1582a) : null);
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
    }

    public final void d(com.google.android.gms.ads.h... hVarArr) {
        com.google.android.gms.ads.k kVar = this.m;
        this.h = hVarArr;
        try {
            K k = this.j;
            if (k != null) {
                k.A1(a(kVar.getContext(), this.h));
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
        kVar.requestLayout();
    }

    public final void e(com.google.android.gms.ads.admanager.a aVar) {
        try {
            this.i = aVar;
            K k = this.j;
            if (k != null) {
                k.A0(aVar != null ? new I5(aVar) : null);
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
    }
}
