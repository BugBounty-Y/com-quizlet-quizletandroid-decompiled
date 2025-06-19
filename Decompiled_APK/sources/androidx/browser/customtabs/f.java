package androidx.browser.customtabs;

import android.os.Bundle;

/* loaded from: classes.dex */
public final class f implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Bundle c;
    public final /* synthetic */ g d;

    public f(g gVar, int i, int i2, Bundle bundle) {
        this.d = gVar;
        this.a = i;
        this.b = i2;
        this.c = bundle;
    }

    @Override // java.lang.Runnable
    public final void run() {
        this.d.b.c(this.a, this.b, this.c);
    }
}
