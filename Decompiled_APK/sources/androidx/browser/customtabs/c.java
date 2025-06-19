package androidx.browser.customtabs;

import android.os.Bundle;

/* loaded from: classes.dex */
public final class c implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ g b;

    public /* synthetic */ c(g gVar, Bundle bundle, int i) {
        this.a = i;
        this.b = gVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.b.getClass();
                break;
            case 1:
                this.b.b.getClass();
                break;
            case 2:
                this.b.b.getClass();
                break;
            default:
                this.b.b.getClass();
                break;
        }
    }

    public c(g gVar, int i, int i2, int i3, int i4, int i5, Bundle bundle) {
        this.a = 2;
        this.b = gVar;
    }
}
