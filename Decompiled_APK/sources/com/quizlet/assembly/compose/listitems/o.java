package com.quizlet.assembly.compose.listitems;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.text.L;
import com.google.android.gms.internal.mlkit_vision_document_scanner.C5;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class o implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ androidx.compose.runtime.internal.d d;
    public final /* synthetic */ boolean e;
    public final /* synthetic */ Function0 f;
    public final /* synthetic */ L g;
    public final /* synthetic */ int h;
    public final /* synthetic */ L i;
    public final /* synthetic */ float j;
    public final /* synthetic */ float k;
    public final /* synthetic */ float l;
    public final /* synthetic */ int m;
    public final /* synthetic */ int n;
    public final /* synthetic */ com.quizlet.ui.models.content.listitem.b o;

    public /* synthetic */ o(com.quizlet.ui.models.content.listitem.b bVar, androidx.compose.ui.q qVar, boolean z, androidx.compose.runtime.internal.d dVar, boolean z2, Function0 function0, L l, int i, L l2, float f, float f2, float f3, int i2, int i3, int i4) {
        this.a = i4;
        this.o = bVar;
        this.b = qVar;
        this.c = z;
        this.d = dVar;
        this.e = z2;
        this.f = function0;
        this.g = l;
        this.h = i;
        this.i = l2;
        this.j = f;
        this.k = f2;
        this.l = f3;
        this.m = i2;
        this.n = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.m | 1);
                C5.g((com.quizlet.ui.models.content.listitem.d) this.o, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, this.l, interfaceC0806l, iH, this.n);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.m | 1);
                C5.l((com.quizlet.ui.models.content.listitem.f) this.o, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, this.l, interfaceC0806l, iH2, this.n);
                break;
        }
        return Unit.a;
    }
}
