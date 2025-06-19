package com.quizlet.features.questiontypes.written.ui;

import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function2 b;
    public final /* synthetic */ InterfaceC0773a0 c;
    public final /* synthetic */ InterfaceC0773a0 d;

    public /* synthetic */ c(Function2 function2, InterfaceC0773a0 interfaceC0773a0, InterfaceC0773a0 interfaceC0773a02, int i) {
        this.a = i;
        this.b = function2;
        this.c = interfaceC0773a0;
        this.d = interfaceC0773a02;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                String str = (String) this.c.getValue();
                Boolean bool = (Boolean) this.d.getValue();
                bool.booleanValue();
                this.b.invoke(str, bool);
                break;
            case 1:
                this.b.invoke((String) this.c.getValue(), (String) this.d.getValue());
                break;
            case 2:
                this.b.invoke((String) this.c.getValue(), (String) this.d.getValue());
                break;
            case 3:
                this.b.invoke((String) this.c.getValue(), (String) this.d.getValue());
                break;
            default:
                this.b.invoke((String) this.c.getValue(), (String) this.d.getValue());
                break;
        }
        return Unit.a;
    }
}
