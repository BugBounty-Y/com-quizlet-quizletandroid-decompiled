package com.quizlet.features.emailconfirmation.ui.composables;

import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes2.dex */
public final class l extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ InterfaceC0773a0 b;
    public final /* synthetic */ androidx.constraintlayout.compose.i c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ l(InterfaceC0773a0 interfaceC0773a0, androidx.constraintlayout.compose.i iVar, int i) {
        super(0);
        this.a = i;
        this.b = interfaceC0773a0;
        this.c = iVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.setValue(Boolean.valueOf(!((Boolean) r0.getValue()).booleanValue()));
                this.c.d = true;
                break;
            case 1:
                this.b.setValue(Boolean.valueOf(!((Boolean) r0.getValue()).booleanValue()));
                this.c.d = true;
                break;
            case 2:
                this.b.setValue(Boolean.valueOf(!((Boolean) r0.getValue()).booleanValue()));
                this.c.d = true;
                break;
            default:
                this.b.setValue(Boolean.valueOf(!((Boolean) r0.getValue()).booleanValue()));
                this.c.d = true;
                break;
        }
        return Unit.a;
    }
}
