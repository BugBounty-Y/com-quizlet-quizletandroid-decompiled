package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.internal.client.zzt;
import java.util.AbstractCollection;
import java.util.HashMap;
import java.util.List;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class Vp {
    public final zzbxs A;
    public final AbstractCollection A0;
    public final String B;
    public final boolean B0;
    public final JSONObject C;
    public final JSONObject D;
    public final String E;
    public final String F;
    public final String G;
    public final String H;
    public final String I;
    public final boolean J;
    public final boolean K;
    public final boolean L;
    public final boolean M;
    public final boolean N;
    public final boolean O;
    public final boolean P;
    public final int Q;
    public final int R;
    public final boolean S;
    public final boolean T;
    public final String U;
    public final C2881yn V;
    public final boolean W;
    public final boolean X;
    public final int Y;
    public final String Z;
    public final List a;
    public final int a0;
    public final int b;
    public final String b0;
    public final List c;
    public final boolean c0;
    public final List d;
    public final androidx.core.os.b d0;
    public final int e;
    public final zzt e0;
    public final List f;
    public final String f0;
    public final List g;
    public final boolean g0;
    public final List h;
    public final JSONObject h0;
    public final List i;
    public final boolean i0;
    public final String j;
    public final JSONObject j0;
    public final String k;
    public final boolean k0;
    public final zzbwj l;
    public final String l0;
    public final List m;
    public final boolean m0;
    public final List n;
    public final String n0;
    public final List o;
    public final String o0;
    public final List p;
    public final String p0;
    public final int q;
    public final boolean q0;
    public final List r;
    public final boolean r0;
    public final Yp s;
    public final int s0;
    public final List t;
    public final String t0;
    public final List u;
    public final AbstractCollection u0;
    public final JSONObject v;
    public final boolean v0;
    public final String w;
    public final HashMap w0;
    public final String x;
    public final com.google.android.gms.auth.api.signin.internal.h x0;
    public final String y;
    public final com.google.android.gms.ads.internal.util.client.g y0;
    public final String z;
    public final double z0;

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:258:0x055d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public Vp(android.util.JsonReader r113) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 3926
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Vp.<init>(android.util.JsonReader):void");
    }

    public static String a(int i) {
        switch (i) {
            case 1:
                return "BANNER";
            case 2:
                return "INTERSTITIAL";
            case 3:
                return "NATIVE_EXPRESS";
            case 4:
                return "NATIVE";
            case 5:
                return "REWARDED";
            case 6:
                return "APP_OPEN_AD";
            case 7:
                return "REWARDED_INTERSTITIAL";
            default:
                return "UNKNOWN";
        }
    }

    public final boolean b() {
        return this.i0 || this.y0 != null;
    }
}
