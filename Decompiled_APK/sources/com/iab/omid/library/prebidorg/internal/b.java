package com.iab.omid.library.prebidorg.internal;

import com.google.android.gms.internal.ads.Sr;
import java.util.Collections;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class b extends Sr {
    public static final b e = new b(2);

    @Override // com.google.android.gms.internal.ads.Sr
    public final void a() {
        Iterator it2 = Collections.unmodifiableCollection(c.c.a).iterator();
        if (it2.hasNext()) {
            throw android.support.v4.media.session.a.d(it2);
        }
    }

    @Override // com.google.android.gms.internal.ads.Sr
    public final void c() {
        Iterator it2 = Collections.unmodifiableCollection(c.c.b).iterator();
        if (it2.hasNext()) {
            throw android.support.v4.media.session.a.d(it2);
        }
    }
}
