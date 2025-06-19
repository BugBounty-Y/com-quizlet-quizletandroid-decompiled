package com.quizlet.features.settings.composables;

import androidx.navigation.H;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class r implements Function0 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ H c;

    public /* synthetic */ r(H h, boolean z, com.quizlet.features.settings.viewmodels.p pVar) {
        this.c = h;
        this.b = z;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                androidx.navigation.r.d(this.c, (this.b ? com.quizlet.features.settings.composables.navigation.k.a : com.quizlet.features.settings.composables.navigation.j.a).e());
                break;
            default:
                androidx.navigation.r.d(this.c, (this.b ? com.quizlet.features.settings.composables.navigation.m.a : com.quizlet.features.settings.composables.navigation.l.a).e());
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ r(boolean z, H h, com.quizlet.features.settings.viewmodels.p pVar) {
        this.b = z;
        this.c = h;
    }
}
