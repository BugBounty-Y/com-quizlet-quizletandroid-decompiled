package com.quizlet.features.practicetest.common.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3394t2;
import com.google.android.gms.internal.mlkit_vision_camera.U1;
import com.quizlet.assembly.compose.modals.x;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class l implements Function2 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ x b;
    public final /* synthetic */ kotlinx.collections.immutable.e c;
    public final /* synthetic */ Function0 d;
    public final /* synthetic */ Function1 e;
    public final /* synthetic */ q f;
    public final /* synthetic */ int g;

    public /* synthetic */ l(x xVar, kotlinx.collections.immutable.e eVar, Function0 function0, Function1 function1, q qVar, int i) {
        this.b = xVar;
        this.c = eVar;
        this.d = function0;
        this.e = function1;
        this.f = qVar;
        this.g = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.g | 1);
                Function0 function0 = this.d;
                U1.a(iH, (InterfaceC0806l) obj, this.f, this.b, function0, this.e, this.c);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.g | 1);
                Function1 function1 = this.e;
                AbstractC3394t2.c(iH2, (InterfaceC0806l) obj, this.f, this.b, this.d, function1, this.c);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ l(x xVar, kotlinx.collections.immutable.e eVar, Function1 function1, Function0 function0, q qVar, int i) {
        this.b = xVar;
        this.c = eVar;
        this.e = function1;
        this.d = function0;
        this.f = qVar;
        this.g = i;
    }
}
