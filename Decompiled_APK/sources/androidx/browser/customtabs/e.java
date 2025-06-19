package androidx.browser.customtabs;

import android.net.Uri;
import android.os.Bundle;

/* loaded from: classes.dex */
public final class e implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Uri b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ Bundle d;
    public final /* synthetic */ g e;

    public e(g gVar, int i, Uri uri, boolean z, Bundle bundle) {
        this.e = gVar;
        this.a = i;
        this.b = uri;
        this.c = z;
        this.d = bundle;
    }

    @Override // java.lang.Runnable
    public final void run() {
        this.e.b.g(this.a, this.b, this.c, this.d);
    }
}
