package com.quizlet.features.setpage.termlist.ads;

import com.google.android.gms.ads.admanager.AdManagerAdView;
import com.google.android.gms.ads.l;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.p;
import kotlin.r;
import kotlinx.coroutines.C5028l;

/* loaded from: classes3.dex */
public final class c implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ C5028l b;

    public /* synthetic */ c(C5028l c5028l, int i) {
        this.a = i;
        this.b = c5028l;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        C5028l c5028l = this.b;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter((l) obj, "it");
                p pVar = r.b;
                c5028l.resumeWith(null);
                return Unit.a;
            case 1:
                AdManagerAdView it2 = (AdManagerAdView) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                p pVar2 = r.b;
                c5028l.resumeWith(new a(it2));
                return Unit.a;
            case 2:
                Intrinsics.checkNotNullParameter((l) obj, "it");
                p pVar3 = r.b;
                c5028l.resumeWith(null);
                return Unit.a;
            case 3:
                AdManagerAdView it3 = (AdManagerAdView) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                p pVar4 = r.b;
                c5028l.resumeWith(new com.quizlet.search.ads.b(it3));
                return Unit.a;
            default:
                p pVar5 = r.b;
                Unit unit = Unit.a;
                c5028l.resumeWith(unit);
                return unit;
        }
    }
}
