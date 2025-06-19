package com.google.android.gms.ads;

import com.google.android.gms.ads.internal.client.v0;

/* loaded from: classes2.dex */
public final class s {
    public final Object a = new Object();
    public v0 b;

    public final boolean a() {
        boolean z;
        synchronized (this.a) {
            z = this.b != null;
        }
        return z;
    }

    public final void b(v0 v0Var) {
        synchronized (this.a) {
            this.b = v0Var;
        }
    }
}
