package com.iab.omid.library.amazon.internal;

import android.view.View;
import com.google.android.gms.internal.ads.Sr;
import com.iab.omid.library.amazon.adsession.k;
import java.util.Collections;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class b extends Sr {
    public static final b e = new b(1);

    @Override // com.google.android.gms.internal.ads.Sr
    public final void b(boolean z) {
        Iterator it2 = Collections.unmodifiableCollection(c.c.a).iterator();
        while (it2.hasNext()) {
            com.iab.omid.library.amazon.publisher.a aVar = ((k) it2.next()).e;
            if (aVar.b.get() != 0) {
                h.a.a(aVar.e(), "setState", z ? "foregrounded" : "backgrounded", aVar.a);
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.google.android.gms.internal.ads.Sr
    public final boolean d() {
        Iterator it2 = Collections.unmodifiableCollection(c.c.b).iterator();
        while (it2.hasNext()) {
            View view = (View) ((k) it2.next()).d.get();
            if (view != null && view.hasWindowFocus()) {
                return true;
            }
        }
        return false;
    }
}
