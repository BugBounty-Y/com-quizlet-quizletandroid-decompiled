package com.quizlet.features.infra.folder.create.composables;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.ui.text.input.A;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.F;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ F b;
    public final /* synthetic */ Function1 c;
    public final /* synthetic */ InterfaceC0773a0 d;

    public /* synthetic */ c(F f, Function1 function1, InterfaceC0773a0 interfaceC0773a0, int i) {
        this.a = i;
        this.b = f;
        this.c = function1;
        this.d = interfaceC0773a0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        A it2 = (A) obj;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(it2, "it");
                F f = this.b;
                if (f.a) {
                    f.a = false;
                } else {
                    this.d.setValue(it2);
                    this.c.invoke(new com.quizlet.features.infra.folder.create.coursefolder.data.f(it2.a.a));
                }
                break;
            default:
                Intrinsics.checkNotNullParameter(it2, "it");
                F f2 = this.b;
                if (f2.a) {
                    f2.a = false;
                } else {
                    this.d.setValue(it2);
                    this.c.invoke(new com.quizlet.features.infra.folder.create.coursefolder.data.f(it2.a.a));
                }
                break;
        }
        return Unit.a;
    }
}
