package com.quizlet.facebook.compose;

import androidx.activity.compose.o;
import coil3.network.g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ o b;

    public /* synthetic */ a(o oVar, int i) {
        this.a = i;
        this.b = oVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() throws Exception {
        switch (this.a) {
            case 0:
                this.b.a(b.a);
                break;
            default:
                this.b.a(g.a());
                break;
        }
        return Unit.a;
    }
}
