package com.google.android.gms.internal.ads;

import android.database.sqlite.SQLiteDatabase;

/* renamed from: com.google.android.gms.internal.ads.lw, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2332lw implements Pv, Xh, Gq {
    public static final C2332lw c;
    public static final C2332lw d;
    public static final C2332lw e;
    public static final C2332lw f;
    public static final C2332lw g;
    public static final C2332lw h;
    public static final C2332lw i;
    public static final C2332lw j;
    public static final C2332lw k;
    public static final C2332lw l;
    public static final C2332lw m;
    public static final C2332lw n;
    public static final C2332lw o;
    public static final C2332lw p;
    public static final C2332lw q;
    public static final C2332lw r;
    public final /* synthetic */ int a;
    public final String b;

    static {
        int i2 = 0;
        c = new C2332lw("ENABLED", i2);
        d = new C2332lw("DISABLED", i2);
        e = new C2332lw("DESTROYED", i2);
        int i3 = 1;
        f = new C2332lw("TINK", i3);
        g = new C2332lw("CRUNCHY", i3);
        h = new C2332lw("NO_PREFIX", i3);
        int i4 = 2;
        i = new C2332lw("ASSUME_AES_GCM", i4);
        j = new C2332lw("ASSUME_XCHACHA20POLY1305", i4);
        k = new C2332lw("ASSUME_CHACHA20POLY1305", i4);
        l = new C2332lw("ASSUME_AES_CTR_HMAC", i4);
        m = new C2332lw("ASSUME_AES_EAX", i4);
        n = new C2332lw("ASSUME_AES_GCM_SIV", i4);
        int i5 = 3;
        o = new C2332lw("TINK", i5);
        p = new C2332lw("CRUNCHY", i5);
        q = new C2332lw("LEGACY", i5);
        r = new C2332lw("NO_PREFIX", i5);
    }

    public /* synthetic */ C2332lw(String str, int i2) {
        this.a = i2;
        this.b = str;
    }

    @Override // com.google.android.gms.internal.ads.Gq
    public Object b(Object obj) {
        ((SQLiteDatabase) obj).delete("offline_buffered_pings", "gws_query_id = ? AND event_state = ?", new String[]{this.b, Integer.toString(0)});
        return null;
    }

    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    public void mo15c(Object obj) {
    }

    public String toString() {
        switch (this.a) {
            case 0:
                return this.b;
            case 1:
                return this.b;
            case 2:
                return this.b;
            case 3:
                return this.b;
            default:
                return super.toString();
        }
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) {
        com.google.android.gms.ads.internal.j.C.h.h(this.b, th);
    }

    @Override // com.google.android.gms.internal.ads.Xh
    /* renamed from: b */
    public void mo16b(Object obj) {
        ((InterfaceC1928ci) obj).A(this.b);
    }
}
