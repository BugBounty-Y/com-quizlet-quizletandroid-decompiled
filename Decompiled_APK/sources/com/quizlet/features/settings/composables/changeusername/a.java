package com.quizlet.features.settings.composables.changeusername;

import androidx.compose.runtime.InterfaceC0773a0;
import com.quizlet.features.settings.viewmodels.C4449g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ C4449g b;
    public final /* synthetic */ InterfaceC0773a0 c;

    public /* synthetic */ a(C4449g c4449g, InterfaceC0773a0 interfaceC0773a0, int i) {
        this.a = i;
        this.b = c4449g;
        this.c = interfaceC0773a0;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.B((String) this.c.getValue());
                break;
            default:
                this.b.B((String) this.c.getValue());
                break;
        }
        return Unit.a;
    }
}
