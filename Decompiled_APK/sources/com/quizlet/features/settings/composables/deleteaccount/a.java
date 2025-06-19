package com.quizlet.features.settings.composables.deleteaccount;

import android.content.Context;
import com.quizlet.features.settings.viewmodels.o;
import kotlin.jvm.functions.Function0;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ C b;
    public final /* synthetic */ com.quizlet.features.infra.google.e c;
    public final /* synthetic */ o d;
    public final /* synthetic */ Context e;

    public /* synthetic */ a(C c, com.quizlet.features.infra.google.e eVar, o oVar, Context context, int i) {
        this.a = i;
        this.b = c;
        this.c = eVar;
        this.d = oVar;
        this.e = context;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return E.A(this.b, null, null, new j(this.c, this.d, this.e, null), 3);
            default:
                return E.A(this.b, null, null, new com.quizlet.features.settings.composables.dialogs.i(this.c, this.d, this.e, null), 3);
        }
    }
}
