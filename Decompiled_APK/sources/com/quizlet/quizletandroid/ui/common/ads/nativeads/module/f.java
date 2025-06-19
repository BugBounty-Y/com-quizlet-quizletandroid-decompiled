package com.quizlet.quizletandroid.ui.common.ads.nativeads.module;

import com.quizlet.quizletandroid.ui.common.ads.C4641h;
import io.reactivex.rxjava3.core.p;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.collections.B;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f {
    public final com.google.mlkit.vision.documentscanner.internal.c a;
    public final com.quizlet.ads.b b;
    public c c;
    public String d;
    public final io.reactivex.rxjava3.disposables.a e;
    public int f;
    public int g;
    public int h;
    public int i;
    public final AtomicBoolean j;
    public ArrayList k;
    public boolean l;

    public f(com.google.mlkit.vision.documentscanner.internal.c adBidTargetsProvider, com.quizlet.ads.b adTargetsManager, C4641h adaptiveBannerAdViewFactory) {
        Intrinsics.checkNotNullParameter(adBidTargetsProvider, "adBidTargetsProvider");
        Intrinsics.checkNotNullParameter(adTargetsManager, "adTargetsManager");
        Intrinsics.checkNotNullParameter(adaptiveBannerAdViewFactory, "adaptiveBannerAdViewFactory");
        this.a = adBidTargetsProvider;
        this.b = adTargetsManager;
        this.e = new io.reactivex.rxjava3.disposables.a();
        this.j = new AtomicBoolean();
        this.k = new ArrayList();
    }

    public final synchronized void a() {
        synchronized (this) {
            try {
                Iterator it2 = this.k.iterator();
                while (it2.hasNext()) {
                    ((d) it2.next()).b.destroy();
                }
                this.k.clear();
            } catch (Throwable th) {
                throw th;
            }
        }
        this.g = 0;
        d(-1);
    }

    public final synchronized void b(int i) {
        if (this.j.getAndSet(true)) {
            return;
        }
        this.g++;
        io.reactivex.rxjava3.internal.observers.e eVarI = p.o(p.f(((d) this.k.get(i)).b), this.a.g(((d) this.k.get(i)).a), this.b.a(), b.c).i(new com.quizlet.analytics.marketing.e(this, 25), io.reactivex.rxjava3.internal.functions.d.e);
        Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
        this.e.b(eVarI);
    }

    public final synchronized int c() {
        int i;
        try {
            ArrayList arrayList = this.k;
            i = 0;
            if (arrayList == null || !arrayList.isEmpty()) {
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    if (((d) it2.next()).c && (i = i + 1) < 0) {
                        B.o();
                        throw null;
                    }
                }
            }
        } finally {
        }
        return i;
    }

    public final void d(int i) {
        com.quizlet.infra.legacysyncengine.tasks.parse.b bVar;
        com.quizlet.infra.legacysyncengine.tasks.parse.b bVar2;
        if (i < 0) {
            c cVar = this.c;
            if (cVar == null || (bVar2 = cVar.e) == null) {
                return;
            }
            ((com.quizlet.quizletandroid.ui.common.ads.nativeads.adapters.a) bVar2.b).notifyDataSetChanged();
            return;
        }
        c cVar2 = this.c;
        if (cVar2 == null || (bVar = cVar2.e) == null) {
            return;
        }
        ((com.quizlet.quizletandroid.ui.common.ads.nativeads.adapters.a) bVar.b).notifyDataSetChanged();
    }

    public final synchronized void e(int i) {
        d dVar = (d) CollectionsKt.O(i, this.k);
        boolean z = true;
        boolean z2 = (dVar == null || dVar.c) ? false : true;
        boolean z3 = c() + this.g < this.i;
        boolean z4 = c() < this.h;
        boolean z5 = i < this.k.size();
        if (this.f >= 2) {
            z = false;
        }
        if (z2 && z3 && z4 && z5 && z) {
            b(i);
        }
    }
}
