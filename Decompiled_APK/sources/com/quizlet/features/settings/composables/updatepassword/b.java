package com.quizlet.features.settings.composables.updatepassword;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3501n3;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3507o3;
import com.quizlet.features.settings.viewmodels.q;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.features.settings.data.models.h b;
    public final /* synthetic */ q c;
    public final /* synthetic */ Function0 d;

    public /* synthetic */ b(com.quizlet.features.settings.data.models.h hVar, q qVar, Function0 function0, int i, int i2) {
        this.a = i2;
        this.b = hVar;
        this.c = qVar;
        this.d = function0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                AbstractC3501n3.b(this.b, this.c, this.d, interfaceC0806l, C0776c.H(7));
                break;
            default:
                AbstractC3507o3.c(this.b, this.c, this.d, interfaceC0806l, C0776c.H(7));
                break;
        }
        return Unit.a;
    }
}
