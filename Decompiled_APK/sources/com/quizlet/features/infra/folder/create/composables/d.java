package com.quizlet.features.infra.folder.create.composables;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.ui.focus.s;
import androidx.compose.ui.text.input.A;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.F;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class d implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ F b;
    public final /* synthetic */ InterfaceC0773a0 c;

    public /* synthetic */ d(F f, InterfaceC0773a0 interfaceC0773a0, int i) {
        this.a = i;
        this.b = f;
        this.c = interfaceC0773a0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        s it2 = (s) obj;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(it2, "it");
                if (it2.a()) {
                    this.b.a = true;
                    InterfaceC0773a0 interfaceC0773a0 = this.c;
                    interfaceC0773a0.setValue(new A(4, AbstractC3205m5.c(0, ((A) interfaceC0773a0.getValue()).a.a.length()), ((A) interfaceC0773a0.getValue()).a.a));
                }
                break;
            default:
                Intrinsics.checkNotNullParameter(it2, "it");
                if (it2.a()) {
                    this.b.a = true;
                    InterfaceC0773a0 interfaceC0773a02 = this.c;
                    interfaceC0773a02.setValue(new A(4, AbstractC3205m5.c(0, ((A) interfaceC0773a02.getValue()).a.a.length()), ((A) interfaceC0773a02.getValue()).a.a));
                }
                break;
        }
        return Unit.a;
    }
}
