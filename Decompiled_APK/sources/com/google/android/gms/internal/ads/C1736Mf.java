package com.google.android.gms.internal.ads;

import java.util.concurrent.Executor;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.Mf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1736Mf implements E5 {
    public InterfaceC2529qe a;
    public final Executor b;
    public final C1706Hf c;
    public final com.google.android.gms.common.util.a d;
    public boolean e = false;
    public boolean f = false;
    public final C1718Jf g = new C1718Jf();

    public C1736Mf(Executor executor, C1706Hf c1706Hf, com.google.android.gms.common.util.a aVar) {
        this.b = executor;
        this.c = c1706Hf;
        this.d = aVar;
    }

    @Override // com.google.android.gms.internal.ads.E5
    public final void R0(D5 d5) {
        boolean z = this.f ? false : d5.j;
        C1718Jf c1718Jf = this.g;
        c1718Jf.a = z;
        c1718Jf.c = this.d.elapsedRealtime();
        c1718Jf.e = d5;
        if (this.e) {
            a();
        }
    }

    public final void a() {
        try {
            JSONObject jSONObjectC = this.c.c(this.g);
            if (this.a != null) {
                this.b.execute(new Qv(21, this, jSONObjectC));
            }
        } catch (JSONException unused) {
            com.google.android.gms.ads.internal.util.A.m();
        }
    }
}
