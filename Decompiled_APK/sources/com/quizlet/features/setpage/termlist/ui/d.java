package com.quizlet.features.setpage.termlist.ui;

import com.quizlet.assembly.compose.menu.s;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class d implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ s b;

    public /* synthetic */ d(s sVar, int i) {
        this.a = i;
        this.b = sVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.a();
                break;
            default:
                this.b.b();
                break;
        }
        return Unit.a;
    }
}
