package com.google.firebase.remoteconfig.internal.rollouts;

import com.google.firebase.crashlytics.internal.b;
import com.google.firebase.remoteconfig.interop.rollouts.d;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ b b;
    public final /* synthetic */ d c;

    public /* synthetic */ a(b bVar, d dVar, int i) {
        this.a = i;
        this.b = bVar;
        this.c = dVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.a(this.c);
                break;
            default:
                this.b.a(this.c);
                break;
        }
    }
}
