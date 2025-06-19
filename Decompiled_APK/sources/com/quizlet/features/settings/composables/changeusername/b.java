package com.quizlet.features.settings.composables.changeusername;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_common.W2;
import com.google.android.gms.internal.mlkit_vision_common.X2;
import com.quizlet.features.settings.viewmodels.C4449g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ C4449g b;
    public final /* synthetic */ Function0 c;

    public /* synthetic */ b(C4449g c4449g, Function0 function0, int i, int i2) {
        this.a = i2;
        this.b = c4449g;
        this.c = function0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                W2.a(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            default:
                X2.a(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
        }
        return Unit.a;
    }
}
