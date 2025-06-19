package com.iab.omid.library.amazon.adsession;

/* loaded from: classes2.dex */
public final class a {
    public final k a;

    public a(k kVar) {
        this.a = kVar;
    }

    public final void a() {
        k kVar = this.a;
        boolean z = kVar.g;
        if (z) {
            throw new IllegalStateException("AdSession is finished");
        }
        if (i.NATIVE != kVar.b.a) {
            throw new IllegalStateException("Impression event is not expected from the Native AdSession");
        }
        if (!kVar.f || z) {
            try {
                kVar.d();
            } catch (Exception unused) {
            }
        }
        if (!kVar.f || kVar.g) {
            return;
        }
        if (kVar.i) {
            throw new IllegalStateException("Impression event can only be sent once");
        }
        com.iab.omid.library.amazon.publisher.a aVar = kVar.e;
        com.iab.omid.library.amazon.internal.h.a.a(aVar.e(), "publishImpressionEvent", aVar.a);
        kVar.i = true;
    }

    public final void b() {
        k kVar = this.a;
        if (!kVar.f) {
            throw new IllegalStateException("AdSession is not started");
        }
        if (kVar.g) {
            throw new IllegalStateException("AdSession is finished");
        }
        if (i.NATIVE != kVar.b.a) {
            throw new IllegalStateException("Impression event is not expected from the Native AdSession");
        }
        if (kVar.j) {
            throw new IllegalStateException("Loaded event can only be sent once");
        }
        com.iab.omid.library.amazon.publisher.a aVar = kVar.e;
        com.iab.omid.library.amazon.internal.h.a.a(aVar.e(), "publishLoadedEvent", null, aVar.a);
        kVar.j = true;
    }
}
