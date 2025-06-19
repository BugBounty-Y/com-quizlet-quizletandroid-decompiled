package androidx.compose.ui.platform;

import android.content.ComponentCallbacks2;
import android.content.res.Configuration;

/* loaded from: classes.dex */
public final class Q implements ComponentCallbacks2 {
    public final /* synthetic */ androidx.compose.ui.res.d a;

    public Q(androidx.compose.ui.res.d dVar) {
        this.a = dVar;
    }

    @Override // android.content.ComponentCallbacks
    public final void onConfigurationChanged(Configuration configuration) {
        this.a.a();
    }

    @Override // android.content.ComponentCallbacks
    public final void onLowMemory() {
        this.a.a();
    }

    @Override // android.content.ComponentCallbacks2
    public final void onTrimMemory(int i) {
        this.a.a();
    }
}
