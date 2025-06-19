package com.quizlet.features.settings.composables.changeuseremail;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_common.T2;
import com.google.android.gms.internal.mlkit_vision_common.U2;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function2 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ com.quizlet.features.settings.viewmodels.l b;
    public final /* synthetic */ Function0 c;
    public final /* synthetic */ Function0 d;

    public /* synthetic */ a(com.quizlet.features.settings.viewmodels.l lVar, Function0 function0, Function0 function02, int i) {
        this.b = lVar;
        this.c = function0;
        this.d = function02;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                T2.a(C0776c.H(1), interfaceC0806l, this.b, this.c, this.d);
                break;
            default:
                U2.a(C0776c.H(1), interfaceC0806l, this.b, this.c, this.d);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ a(Function0 function0, Function0 function02, com.quizlet.features.settings.viewmodels.l lVar, int i) {
        this.c = function0;
        this.d = function02;
        this.b = lVar;
    }
}
