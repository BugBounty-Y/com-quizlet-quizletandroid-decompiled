package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class Ti implements E5 {
    public final /* synthetic */ String a;
    public final /* synthetic */ Ui b;

    public Ti(Ui ui, String str) {
        this.a = str;
        this.b = ui;
    }

    /* JADX WARN: Type inference failed for: r0v10, types: [com.google.android.gms.internal.ads.uj, com.google.android.gms.internal.ads.x5] */
    /* JADX WARN: Type inference failed for: r0v6, types: [com.google.android.gms.internal.ads.uj, com.google.android.gms.internal.ads.x5] */
    /* JADX WARN: Type inference failed for: r2v1, types: [com.google.android.gms.internal.ads.uj, com.google.android.gms.internal.ads.x5] */
    /* JADX WARN: Type inference failed for: r2v4, types: [com.google.android.gms.internal.ads.uj, com.google.android.gms.internal.ads.x5] */
    /* JADX WARN: Type inference failed for: r3v1, types: [com.google.android.gms.internal.ads.uj, com.google.android.gms.internal.ads.x5] */
    /* JADX WARN: Type inference failed for: r3v4, types: [com.google.android.gms.internal.ads.uj, com.google.android.gms.internal.ads.x5] */
    @Override // com.google.android.gms.internal.ads.E5
    public final void R0(D5 d5) {
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.M1)).booleanValue()) {
            if (d5.j) {
                Ui ui = this.b;
                if (ui.u != null) {
                    ui.F.put(this.a, Boolean.TRUE);
                    ?? r0 = ui.u;
                    if (r0 == 0) {
                        return;
                    }
                    ui.b(r0.f(), ui.u.k(), ui.u.l(), true);
                    return;
                }
                return;
            }
            return;
        }
        synchronized (this) {
            try {
                if (d5.j) {
                    Ui ui2 = this.b;
                    if (ui2.u != null) {
                        ui2.F.put(this.a, Boolean.TRUE);
                        ?? r02 = ui2.u;
                        if (r02 == 0) {
                        } else {
                            ui2.b(r02.f(), ui2.u.k(), ui2.u.l(), true);
                        }
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
