package com.quizlet.features.practicetest.results.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import androidx.transition.C1413p;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class e implements Function2 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ String b;
    public final /* synthetic */ String c;
    public final /* synthetic */ q d;
    public final /* synthetic */ int e;

    public /* synthetic */ e(String str, String str2, q qVar, int i) {
        this.b = str;
        this.c = str2;
        this.d = qVar;
        this.e = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(1);
                q qVar = this.d;
                C1413p.g(iH, this.e, (InterfaceC0806l) obj, qVar, this.b, this.c);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.e | 1);
                String str = this.c;
                q qVar2 = this.d;
                C1413p.e(this.b, str, qVar2, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ e(String str, String str2, q qVar, int i, int i2) {
        this.b = str;
        this.c = str2;
        this.d = qVar;
        this.e = i2;
    }
}
