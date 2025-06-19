package com.quizlet.assembly.compose.modals;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.ui.platform.C0957n0;
import androidx.compose.ui.platform.Q0;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes2.dex */
public final /* synthetic */ class u implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Q0 b;
    public final /* synthetic */ Function1 c;
    public final /* synthetic */ InterfaceC0773a0 d;

    public /* synthetic */ u(Q0 q0, Function1 function1, InterfaceC0773a0 interfaceC0773a0, int i) {
        this.a = i;
        this.b = q0;
        this.c = function1;
        this.d = interfaceC0773a0;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                Q0 q0 = this.b;
                if (q0 != null) {
                    ((C0957n0) q0).a();
                }
                this.c.invoke((String) this.d.getValue());
                break;
            case 1:
                Q0 q02 = this.b;
                if (q02 != null) {
                    ((C0957n0) q02).a();
                }
                this.c.invoke((String) this.d.getValue());
                break;
            case 2:
                Q0 q03 = this.b;
                if (q03 != null) {
                    ((C0957n0) q03).a();
                }
                this.c.invoke((String) this.d.getValue());
                break;
            default:
                Q0 q04 = this.b;
                if (q04 != null) {
                    ((C0957n0) q04).a();
                }
                this.c.invoke((String) this.d.getValue());
                break;
        }
        return Unit.a;
    }
}
