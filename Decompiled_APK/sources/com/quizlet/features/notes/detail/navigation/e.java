package com.quizlet.features.notes.detail.navigation;

import androidx.navigation.B;
import androidx.navigation.H;
import androidx.navigation.L;
import com.quizlet.local.datastore.preferences.C4566c0;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class e implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ H b;

    public /* synthetic */ e(H h, int i) {
        this.a = i;
        this.b = h;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                com.quizlet.report.ui.b it2 = (com.quizlet.report.ui.b) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                this.b.e();
                break;
            default:
                L navOptions = (L) obj;
                Intrinsics.checkNotNullParameter(navOptions, "$this$navOptions");
                B bG = this.b.b.g();
                navOptions.a(bG != null ? bG.b.c : 0, new C4566c0(18));
                break;
        }
        return Unit.a;
    }
}
