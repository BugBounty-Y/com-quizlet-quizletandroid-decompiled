package com.google.android.gms.internal.ads;

import android.app.Activity;
import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.fm, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2063fm {
    public final Activity a;
    public final com.google.android.gms.ads.internal.overlay.d b;
    public final String c;
    public final String d;

    public C2063fm(Activity activity, com.google.android.gms.ads.internal.overlay.d dVar, String str, String str2) {
        this.a = activity;
        this.b = dVar;
        this.c = str;
        this.d = str2;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof C2063fm) {
            C2063fm c2063fm = (C2063fm) obj;
            if (this.a.equals(c2063fm.a)) {
                com.google.android.gms.ads.internal.overlay.d dVar = c2063fm.b;
                com.google.android.gms.ads.internal.overlay.d dVar2 = this.b;
                if (dVar2 != null ? dVar2.equals(dVar) : dVar == null) {
                    String str = c2063fm.c;
                    String str2 = this.c;
                    if (str2 != null ? str2.equals(str) : str == null) {
                        String str3 = c2063fm.d;
                        String str4 = this.d;
                        if (str4 != null ? str4.equals(str3) : str3 == null) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() ^ 1000003;
        com.google.android.gms.ads.internal.overlay.d dVar = this.b;
        int iHashCode2 = ((iHashCode * 1000003) ^ (dVar == null ? 0 : dVar.hashCode())) * 1000003;
        String str = this.c;
        int iHashCode3 = (iHashCode2 ^ (str == null ? 0 : str.hashCode())) * 1000003;
        String str2 = this.d;
        return iHashCode3 ^ (str2 != null ? str2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sbH = AbstractC0147y.h("OfflineUtilsParams{activity=", this.a.toString(), ", adOverlay=", String.valueOf(this.b), ", gwsQueryId=");
        sbH.append(this.c);
        sbH.append(", uri=");
        return android.support.v4.media.session.a.t(sbH, this.d, "}");
    }
}
