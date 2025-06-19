package com.google.android.gms.internal.ads;

import java.lang.ref.WeakReference;

/* loaded from: classes2.dex */
public final class Fh implements Runnable {
    public final /* synthetic */ int a;
    public final WeakReference b;

    public /* synthetic */ Fh(Gh gh, int i) {
        this.a = i;
        switch (i) {
            case 1:
                this.b = new WeakReference(gh);
                break;
            default:
                this.b = new WeakReference(gh);
                break;
        }
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                Gh gh = (Gh) this.b.get();
                if (gh != null) {
                    gh.j1(new C1927ch(17));
                    break;
                }
                break;
            default:
                Gh gh2 = (Gh) this.b.get();
                if (gh2 != null) {
                    gh2.j1(new C1927ch(18));
                    break;
                }
                break;
        }
    }
}
