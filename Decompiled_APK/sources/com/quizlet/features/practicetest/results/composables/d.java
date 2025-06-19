package com.quizlet.features.practicetest.results.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import androidx.transition.C1413p;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class d implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ int c;
    public final /* synthetic */ int d;
    public final /* synthetic */ int e;
    public final /* synthetic */ q f;
    public final /* synthetic */ int g;

    public /* synthetic */ d(String str, int i, int i2, int i3, q qVar, int i4, int i5) {
        this.a = 0;
        this.b = str;
        this.c = i;
        this.d = i2;
        this.e = i3;
        this.f = qVar;
        this.g = i4;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(1);
                q qVar = this.f;
                int i = this.g;
                C1413p.h(this.b, this.c, this.d, this.e, qVar, i, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.g | 1);
                int i2 = this.e;
                q qVar2 = this.f;
                C1413p.d(this.b, this.c, this.d, i2, qVar2, (InterfaceC0806l) obj, iH2);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(this.g | 1);
                int i3 = this.e;
                q qVar3 = this.f;
                C1413p.f(this.b, this.c, this.d, i3, qVar3, (InterfaceC0806l) obj, iH3);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ d(String str, int i, int i2, int i3, q qVar, int i4, int i5, byte b) {
        this.a = i5;
        this.b = str;
        this.c = i;
        this.d = i2;
        this.e = i3;
        this.f = qVar;
        this.g = i4;
    }
}
