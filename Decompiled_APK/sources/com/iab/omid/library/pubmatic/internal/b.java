package com.iab.omid.library.pubmatic.internal;

import android.annotation.SuppressLint;
import android.view.View;
import java.util.Iterator;

/* loaded from: classes2.dex */
public class b extends d {

    @SuppressLint({"StaticFieldLeak"})
    private static b d = new b();

    private b() {
    }

    public static b g() {
        return d;
    }

    @Override // com.iab.omid.library.pubmatic.internal.d
    public void b(boolean z) {
        Iterator<com.iab.omid.library.pubmatic.adsession.a> it2 = c.c().b().iterator();
        while (it2.hasNext()) {
            it2.next().getAdSessionStatePublisher().a(z);
        }
    }

    @Override // com.iab.omid.library.pubmatic.internal.d
    public boolean d() {
        Iterator<com.iab.omid.library.pubmatic.adsession.a> it2 = c.c().a().iterator();
        while (it2.hasNext()) {
            View viewC = it2.next().c();
            if (viewC != null && viewC.hasWindowFocus()) {
                return true;
            }
        }
        return false;
    }
}
