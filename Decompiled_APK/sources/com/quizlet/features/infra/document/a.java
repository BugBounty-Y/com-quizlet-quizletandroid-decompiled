package com.quizlet.features.infra.document;

import android.content.Intent;
import androidx.activity.compose.o;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ o b;
    public final /* synthetic */ Intent c;

    public /* synthetic */ a(o oVar, Intent intent, int i) {
        this.a = i;
        this.b = oVar;
        this.c = intent;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() throws Exception {
        switch (this.a) {
            case 0:
                this.b.a(this.c);
                break;
            default:
                o oVar = this.b;
                if (oVar != null) {
                    oVar.a(this.c);
                }
                break;
        }
        return Unit.a;
    }
}
