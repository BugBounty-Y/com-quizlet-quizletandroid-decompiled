package com.braze;

import androidx.compose.runtime.InterfaceC0773a0;
import java.io.Serializable;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final /* synthetic */ class r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ r(Serializable serializable, Object obj, boolean z, int i) {
        this.a = i;
        this.c = serializable;
        this.d = obj;
        this.b = z;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                break;
            case 1:
                break;
            case 2:
                break;
            case 3:
                if (this.b) {
                    com.quizlet.assembly.compose.modals.x xVar = (com.quizlet.assembly.compose.modals.x) this.c;
                    ((Function0) ((InterfaceC0773a0) this.d).getValue()).invoke();
                    xVar.c();
                }
                break;
            case 4:
                if (this.b) {
                    com.quizlet.assembly.compose.modals.x xVar2 = (com.quizlet.assembly.compose.modals.x) this.d;
                    ((Function0) this.c).invoke();
                    xVar2.c();
                }
                break;
            case 5:
                if (this.b) {
                    ((com.quizlet.assembly.compose.menu.s) this.c).b();
                } else {
                    ((com.quizlet.assembly.compose.menu.s) this.d).b();
                }
                break;
            default:
                ((Function1) this.c).invoke(new com.quizlet.features.onboarding.ell.i(this.b, (com.quizlet.features.onboarding.ell.m) this.d));
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ r(Function1 function1, boolean z, com.quizlet.features.onboarding.ell.m mVar) {
        this.a = 6;
        this.c = function1;
        this.b = z;
        this.d = mVar;
    }

    public /* synthetic */ r(boolean z, Object obj, Object obj2, int i) {
        this.a = i;
        this.b = z;
        this.c = obj;
        this.d = obj2;
    }
}
