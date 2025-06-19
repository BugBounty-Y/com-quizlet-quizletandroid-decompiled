package com.quizlet.learn.checkpoint.ui;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3525r4;
import com.quizlet.learn.ui.progress.g;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ g b;
    public final /* synthetic */ q c;
    public final /* synthetic */ int d;

    public /* synthetic */ a(g gVar, q qVar, int i, int i2) {
        this.a = 0;
        this.b = gVar;
        this.c = qVar;
        this.d = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                AbstractC3525r4.c(this.b, this.c, this.d, interfaceC0806l, C0776c.H(1));
                break;
            case 1:
                AbstractC3525r4.a(this.b, this.c, interfaceC0806l, C0776c.H(this.d | 1));
                break;
            default:
                AbstractC3525r4.b(this.b, this.c, interfaceC0806l, C0776c.H(this.d | 1));
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ a(g gVar, q qVar, int i, int i2, byte b) {
        this.a = i2;
        this.b = gVar;
        this.c = qVar;
        this.d = i;
    }
}
