package com.google.android.gms.internal.ads;

import android.view.View;
import java.util.Collections;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class Pr extends Sr {
    public static final Pr e = new Pr(0);

    @Override // com.google.android.gms.internal.ads.Sr
    public final void t(boolean z) {
        Iterator it2 = Collections.unmodifiableCollection(Qr.c.a).iterator();
        while (it2.hasNext()) {
            Zr zr = ((Hr) it2.next()).d;
            if (zr.b.get() != 0) {
                AbstractC1795We.o(zr.a(), "setState", true != z ? "backgrounded" : "foregrounded", zr.a);
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.google.android.gms.internal.ads.Sr
    public final boolean u() {
        Iterator it2 = Collections.unmodifiableCollection(Qr.c.b).iterator();
        while (it2.hasNext()) {
            View view = (View) ((Hr) it2.next()).c.get();
            if (view != null && view.hasWindowFocus()) {
                return true;
            }
        }
        return false;
    }
}
