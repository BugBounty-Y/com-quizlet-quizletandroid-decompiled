package androidx.browser.customtabs;

import android.os.Bundle;

/* loaded from: classes.dex */
public final class d implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ Bundle c;
    public final /* synthetic */ g d;

    public /* synthetic */ d(g gVar, String str, Bundle bundle, int i) {
        this.a = i;
        this.d = gVar;
        this.b = str;
        this.c = bundle;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.d.b.a(this.c, this.b);
                break;
            default:
                this.d.b.f(this.c, this.b);
                break;
        }
    }
}
