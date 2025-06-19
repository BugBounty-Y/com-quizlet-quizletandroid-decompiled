package com.quizlet.quizletandroid.ui.common.ads.nativeads.module;

import androidx.compose.material3.C0676l1;
import androidx.lifecycle.InterfaceC1250k;
import androidx.lifecycle.J;
import com.google.android.gms.ads.admanager.AdManagerAdView;
import com.google.android.gms.ads.k;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements InterfaceC1250k {
    public final androidx.work.impl.model.c a;
    public final C0676l1 b;
    public final f c;
    public AtomicReference d;
    public com.quizlet.infra.legacysyncengine.tasks.parse.b e;
    public int f;

    public c(androidx.work.impl.model.c userProperties, C0676l1 adapterCalculator, f adFetcher) {
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(adapterCalculator, "adapterCalculator");
        Intrinsics.checkNotNullParameter(adFetcher, "adFetcher");
        this.a = userProperties;
        this.b = adapterCalculator;
        this.c = adFetcher;
        io.reactivex.rxjava3.disposables.d dVar = new io.reactivex.rxjava3.disposables.d(io.reactivex.rxjava3.internal.functions.d.b, 0);
        Intrinsics.checkNotNullExpressionValue(dVar, "empty(...)");
        this.d = dVar;
        this.f = 1;
    }

    public final k a(int i) {
        int iA = this.b.a(i);
        f fVar = this.c;
        synchronized (fVar) {
            AdManagerAdView adManagerAdView = null;
            if (iA >= 0) {
                try {
                    if (iA < fVar.i && iA < fVar.k.size()) {
                        Object obj = fVar.k.get(iA);
                        Intrinsics.checkNotNullExpressionValue(obj, "get(...)");
                        d dVar = (d) obj;
                        if (dVar.c) {
                            adManagerAdView = dVar.b;
                        } else {
                            fVar.e(iA);
                        }
                        return adManagerAdView;
                    }
                } finally {
                }
            }
            return null;
        }
    }

    public final int b(int i) {
        int i2;
        int iC = this.c.c();
        C0676l1 c0676l1 = this.b;
        int i3 = c0676l1.a;
        if (i >= i3) {
            int i4 = c0676l1.b;
            i2 = 1;
            if (i4 != 0) {
                i2 = 1 + ((i - i3) / i4);
            }
        } else {
            i2 = 0;
        }
        return Math.max(0, Math.min(iC, i2)) + i;
    }

    public final int c(int i, int i2) {
        int iC = this.c.c();
        C0676l1 c0676l1 = this.b;
        int iMin = 0;
        if (iC > 0) {
            if (i2 > 0) {
                int i3 = c0676l1.a;
                if (i2 >= i3 + 1) {
                    int i4 = c0676l1.b;
                    iMin = i4 == 0 ? 1 : ((i2 - i3) / i4) + 1;
                }
            }
            iMin = Math.min(iC, iMin);
        }
        return i - Math.min(c0676l1.a(i) + 1, iMin);
    }

    public final boolean e(int i) {
        int i2 = this.f;
        C0676l1 c0676l1 = this.b;
        int i3 = c0676l1.b;
        if (i3 == 0) {
            if (i != c0676l1.a) {
                return false;
            }
        } else if ((i - c0676l1.a) % (i3 + 1) != 0) {
            return false;
        }
        if (i2 == 0) {
            return false;
        }
        int iA = c0676l1.a(i);
        return i >= c0676l1.a && iA >= 0 && iA < i2 && a(i) != null;
    }

    /* JADX WARN: Type inference failed for: r2v1, types: [io.reactivex.rxjava3.disposables.b, java.util.concurrent.atomic.AtomicReference] */
    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onDestroy(J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
        Intrinsics.checkNotNullParameter(owner, "owner");
        this.d.dispose();
        f fVar = this.c;
        fVar.e.dispose();
        fVar.a();
        fVar.l = true;
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onPause(J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
        Intrinsics.checkNotNullParameter(owner, "owner");
        Iterator it2 = this.c.k.iterator();
        while (it2.hasNext()) {
            ((d) it2.next()).b.pause();
        }
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onResume(J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
        Intrinsics.checkNotNullParameter(owner, "owner");
        Iterator it2 = this.c.k.iterator();
        while (it2.hasNext()) {
            ((d) it2.next()).b.resume();
        }
    }
}
