package com.google.android.gms.measurement.internal;

import android.content.pm.PackageManager;
import android.os.SystemClock;
import android.util.Pair;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Locale;

/* loaded from: classes2.dex */
public final class a1 extends m1 {
    public final HashMap e;
    public final N f;
    public final N g;
    public final N h;
    public final N i;
    public final N j;
    public final N k;

    public a1(r1 r1Var) {
        super(r1Var);
        this.e = new HashMap();
        O o = ((Y) this.b).h;
        Y.h(o);
        this.f = new N(o, "last_delete_stale", 0L);
        O o2 = ((Y) this.b).h;
        Y.h(o2);
        this.g = new N(o2, "last_delete_stale_batch", 0L);
        O o3 = ((Y) this.b).h;
        Y.h(o3);
        this.h = new N(o3, "backoff", 0L);
        O o4 = ((Y) this.b).h;
        Y.h(o4);
        this.i = new N(o4, "last_upload", 0L);
        O o5 = ((Y) this.b).h;
        Y.h(o5);
        this.j = new N(o5, "last_upload_attempt", 0L);
        O o6 = ((Y) this.b).h;
        Y.h(o6);
        this.k = new N(o6, "midnight_offset", 0L);
    }

    @Override // com.google.android.gms.measurement.internal.m1
    public final void V() {
    }

    public final Pair W(String str) {
        Z0 z0;
        com.google.android.gms.ads.identifier.a aVarA;
        S();
        Y y = (Y) this.b;
        y.n.getClass();
        long jElapsedRealtime = SystemClock.elapsedRealtime();
        HashMap map = this.e;
        Z0 z02 = (Z0) map.get(str);
        if (z02 != null && jElapsedRealtime < z02.c) {
            return new Pair(z02.a, Boolean.valueOf(z02.b));
        }
        C3891s c3891s = AbstractC3893t.b;
        C3864e c3864e = y.g;
        long jA0 = c3864e.a0(str, c3891s) + jElapsedRealtime;
        try {
            try {
                aVarA = com.google.android.gms.ads.identifier.b.a(y.a);
            } catch (PackageManager.NameNotFoundException unused) {
                if (z02 != null && jElapsedRealtime < z02.c + c3864e.a0(str, AbstractC3893t.c)) {
                    return new Pair(z02.a, Boolean.valueOf(z02.b));
                }
                aVarA = null;
            }
        } catch (Exception e) {
            I i = y.i;
            Y.k(i);
            i.n.g("Unable to get advertising id", e);
            z0 = new Z0("", jA0, false);
        }
        if (aVarA == null) {
            return new Pair("00000000-0000-0000-0000-000000000000", Boolean.FALSE);
        }
        String str2 = aVarA.a;
        boolean z = aVarA.b;
        z0 = str2 != null ? new Z0(str2, jA0, z) : new Z0("", jA0, z);
        map.put(str, z0);
        return new Pair(z0.a, Boolean.valueOf(z0.b));
    }

    public final String X(String str, boolean z) throws NoSuchAlgorithmException {
        S();
        String str2 = z ? (String) W(str).first : "00000000-0000-0000-0000-000000000000";
        MessageDigest messageDigestC0 = x1.c0();
        if (messageDigestC0 == null) {
            return null;
        }
        return String.format(Locale.US, "%032X", new BigInteger(1, messageDigestC0.digest(str2.getBytes())));
    }
}
