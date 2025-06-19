package com.quizlet.quizletandroid.ui.common.ads.nativeads.module;

import com.google.android.gms.ads.l;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends com.google.android.gms.ads.d {
    public final /* synthetic */ f b;
    public final /* synthetic */ int c;

    public e(f fVar, int i) {
        this.b = fVar;
        this.c = i;
    }

    @Override // com.google.android.gms.ads.d
    public final void onAdFailedToLoad(l error) {
        Intrinsics.checkNotNullParameter(error, "error");
        timber.log.c.a.a("Ad failed to load with error (%s)", error);
        f fVar = this.b;
        fVar.j.set(false);
        fVar.f++;
        fVar.g--;
        int i = error.a;
        if (i == 0 || i == 2) {
            fVar.e(this.c);
        }
    }

    @Override // com.google.android.gms.ads.d
    public final void onAdLoaded() {
        f fVar = this.b;
        int i = this.c;
        synchronized (fVar) {
            if (fVar.l) {
                return;
            }
            fVar.j.set(false);
            ((d) fVar.k.get(i)).c = true;
            fVar.d(i);
            fVar.g--;
            fVar.f = 0;
            fVar.e(i + 1);
        }
    }
}
