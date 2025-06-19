package com.quizlet.learn.ui.onboarding;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_common.z4;
import com.quizlet.learn.data.onboarding.C4551a;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class f implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ C4551a c;
    public final /* synthetic */ com.quizlet.learn.viewmodel.i d;
    public final /* synthetic */ q e;

    public /* synthetic */ f(String str, C4551a c4551a, com.quizlet.learn.viewmodel.i iVar, q qVar, int i, int i2) {
        this.a = i2;
        this.b = str;
        this.c = c4551a;
        this.d = iVar;
        this.e = qVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(1);
                C4551a c4551a = this.c;
                com.quizlet.learn.viewmodel.i iVar = this.d;
                q qVar = this.e;
                z4.a(this.b, c4551a, iVar, qVar, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1);
                C4551a c4551a2 = this.c;
                com.quizlet.learn.viewmodel.i iVar2 = this.d;
                q qVar2 = this.e;
                z4.c(this.b, c4551a2, iVar2, qVar2, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }
}
