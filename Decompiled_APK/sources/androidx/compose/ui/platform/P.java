package androidx.compose.ui.platform;

import android.content.ComponentCallbacks2;
import android.content.res.Configuration;
import java.lang.ref.WeakReference;
import java.util.Iterator;
import java.util.Map;

/* loaded from: classes.dex */
public final class P implements ComponentCallbacks2 {
    public final /* synthetic */ Configuration a;
    public final /* synthetic */ androidx.compose.ui.res.c b;

    public P(Configuration configuration, androidx.compose.ui.res.c cVar) {
        this.a = configuration;
        this.b = cVar;
    }

    @Override // android.content.ComponentCallbacks
    public final void onConfigurationChanged(Configuration configuration) {
        Configuration configuration2 = this.a;
        int iUpdateFrom = configuration2.updateFrom(configuration);
        Iterator it2 = this.b.a.entrySet().iterator();
        while (it2.hasNext()) {
            androidx.compose.ui.res.a aVar = (androidx.compose.ui.res.a) ((WeakReference) ((Map.Entry) it2.next()).getValue()).get();
            if (aVar == null || Configuration.needNewResources(iUpdateFrom, aVar.b)) {
                it2.remove();
            }
        }
        configuration2.setTo(configuration);
    }

    @Override // android.content.ComponentCallbacks
    public final void onLowMemory() {
        this.b.a.clear();
    }

    @Override // android.content.ComponentCallbacks2
    public final void onTrimMemory(int i) {
        this.b.a.clear();
    }
}
