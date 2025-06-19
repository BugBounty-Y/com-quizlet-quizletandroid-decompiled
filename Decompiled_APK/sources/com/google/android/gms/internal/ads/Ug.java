package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import com.google.android.gms.ads.internal.client.C1616r0;
import com.google.android.gms.ads.internal.client.zzv;
import java.util.List;

/* loaded from: classes2.dex */
public final class Ug extends AbstractBinderC2814x5 implements com.google.android.gms.ads.internal.client.s0 {
    public final String a;
    public final String b;
    public final String c;
    public final String d;
    public final List e;
    public final long f;
    public final String g;
    public final C2923zm h;
    public final Bundle i;
    public final double j;

    /* JADX WARN: Removed duplicated region for block: B:32:0x0090  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public Ug(com.google.android.gms.internal.ads.Vp r3, java.lang.String r4, com.google.android.gms.internal.ads.C2923zm r5, com.google.android.gms.internal.ads.Xp r6, java.lang.String r7) throws org.json.JSONException {
        /*
            r2 = this;
            java.lang.String r0 = "com.google.android.gms.ads.internal.client.IResponseInfo"
            r2.<init>(r0)
            r0 = 0
            if (r3 != 0) goto La
            r1 = r0
            goto Lc
        La:
            java.lang.String r1 = r3.b0
        Lc:
            r2.b = r1
            r2.c = r7
            if (r6 != 0) goto L14
            r7 = r0
            goto L16
        L14:
            java.lang.String r7 = r6.b
        L16:
            r2.d = r7
            java.lang.String r7 = "com.google.android.gms.ads.mediation.customevent.CustomEventAdapter"
            boolean r7 = r7.equals(r4)
            if (r7 != 0) goto L28
            java.lang.String r7 = "com.google.ads.mediation.customevent.CustomEventAdapter"
            boolean r7 = r7.equals(r4)
            if (r7 == 0) goto L32
        L28:
            if (r3 == 0) goto L32
            org.json.JSONObject r7 = r3.v     // Catch: org.json.JSONException -> L32
            java.lang.String r1 = "class_name"
            java.lang.String r0 = r7.getString(r1)     // Catch: org.json.JSONException -> L32
        L32:
            if (r0 == 0) goto L35
            r4 = r0
        L35:
            r2.a = r4
            java.util.List r4 = r5.a
            r2.e = r4
            r2.h = r5
            if (r3 != 0) goto L42
            r3 = 0
            goto L44
        L42:
            double r3 = r3.z0
        L44:
            r2.j = r3
            com.google.android.gms.ads.internal.j r3 = com.google.android.gms.ads.internal.j.C
            com.google.android.gms.common.util.b r3 = r3.k
            r3.getClass()
            long r3 = java.lang.System.currentTimeMillis()
            r0 = 1000(0x3e8, double:4.94E-321)
            long r3 = r3 / r0
            r2.f = r3
            com.google.android.gms.internal.ads.s7 r3 = com.google.android.gms.internal.ads.AbstractC2773w7.J6
            com.google.android.gms.ads.internal.client.r r4 = com.google.android.gms.ads.internal.client.r.d
            com.google.android.gms.internal.ads.u7 r5 = r4.c
            java.lang.Object r3 = r5.a(r3)
            java.lang.Boolean r3 = (java.lang.Boolean) r3
            boolean r3 = r3.booleanValue()
            if (r3 == 0) goto L6f
            if (r6 == 0) goto L6f
            android.os.Bundle r3 = r6.k
            r2.i = r3
            goto L76
        L6f:
            android.os.Bundle r3 = new android.os.Bundle
            r3.<init>()
            r2.i = r3
        L76:
            com.google.android.gms.internal.ads.s7 r3 = com.google.android.gms.internal.ads.AbstractC2773w7.l9
            com.google.android.gms.internal.ads.u7 r4 = r4.c
            java.lang.Object r3 = r4.a(r3)
            java.lang.Boolean r3 = (java.lang.Boolean) r3
            boolean r3 = r3.booleanValue()
            if (r3 == 0) goto L90
            if (r6 == 0) goto L90
            java.lang.String r3 = r6.i
            boolean r4 = android.text.TextUtils.isEmpty(r3)
            if (r4 == 0) goto L92
        L90:
            java.lang.String r3 = ""
        L92:
            r2.g = r3
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Ug.<init>(com.google.android.gms.internal.ads.Vp, java.lang.String, com.google.android.gms.internal.ads.zm, com.google.android.gms.internal.ads.Xp, java.lang.String):void");
    }

    public static com.google.android.gms.ads.internal.client.s0 e4(IBinder iBinder) {
        if (iBinder == null) {
            return null;
        }
        IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IResponseInfo");
        return iInterfaceQueryLocalInterface instanceof com.google.android.gms.ads.internal.client.s0 ? (com.google.android.gms.ads.internal.client.s0) iInterfaceQueryLocalInterface : new C1616r0(iBinder);
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        switch (i) {
            case 1:
                parcel2.writeNoException();
                parcel2.writeString(this.a);
                return true;
            case 2:
                parcel2.writeNoException();
                parcel2.writeString(this.b);
                return true;
            case 3:
                parcel2.writeNoException();
                parcel2.writeTypedList(this.e);
                return true;
            case 4:
                zzv zzvVarF = f();
                parcel2.writeNoException();
                AbstractC2857y5.d(parcel2, zzvVarF);
                return true;
            case 5:
                parcel2.writeNoException();
                AbstractC2857y5.d(parcel2, this.i);
                return true;
            case 6:
                parcel2.writeNoException();
                parcel2.writeString(this.c);
                return true;
            default:
                return false;
        }
    }

    @Override // com.google.android.gms.ads.internal.client.s0
    public final zzv f() {
        C2923zm c2923zm = this.h;
        if (c2923zm != null) {
            return c2923zm.f;
        }
        return null;
    }

    @Override // com.google.android.gms.ads.internal.client.s0
    public final String g() {
        return this.c;
    }

    @Override // com.google.android.gms.ads.internal.client.s0
    public final String h() {
        return this.a;
    }

    @Override // com.google.android.gms.ads.internal.client.s0
    public final List i() {
        return this.e;
    }

    @Override // com.google.android.gms.ads.internal.client.s0
    public final Bundle zze() {
        return this.i;
    }

    @Override // com.google.android.gms.ads.internal.client.s0
    public final String zzi() {
        return this.b;
    }
}
