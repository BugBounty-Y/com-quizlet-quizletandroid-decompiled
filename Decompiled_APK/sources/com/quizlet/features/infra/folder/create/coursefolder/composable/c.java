package com.quizlet.features.infra.folder.create.coursefolder.composable;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.n;
import androidx.compose.ui.q;
import androidx.compose.ui.text.input.A;
import com.google.android.gms.internal.mlkit_vision_barcode.M5;
import com.google.android.gms.internal.mlkit_vision_barcode.O5;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ A b;
    public final /* synthetic */ kotlinx.collections.immutable.b c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ boolean e;
    public final /* synthetic */ boolean f;
    public final /* synthetic */ com.quizlet.features.infra.folder.create.data.b g;
    public final /* synthetic */ com.quizlet.features.infra.folder.create.coursefolder.data.m h;
    public final /* synthetic */ Function1 i;
    public final /* synthetic */ Function1 j;
    public final /* synthetic */ Function1 k;
    public final /* synthetic */ Function0 l;
    public final /* synthetic */ Function0 m;
    public final /* synthetic */ Function0 n;
    public final /* synthetic */ Function0 o;
    public final /* synthetic */ Function1 p;
    public final /* synthetic */ Function0 q;
    public final /* synthetic */ q r;

    public /* synthetic */ c(q qVar, A a, kotlinx.collections.immutable.b bVar, boolean z, boolean z2, boolean z3, com.quizlet.features.infra.folder.create.data.b bVar2, com.quizlet.features.infra.folder.create.coursefolder.data.m mVar, Function1 function1, Function1 function12, Function1 function13, Function0 function0, Function0 function02, Function0 function03, Function0 function04, Function1 function14, Function0 function05, int i, int i2) {
        this.a = i2;
        this.r = qVar;
        this.b = a;
        this.c = bVar;
        this.d = z;
        this.e = z2;
        this.f = z3;
        this.g = bVar2;
        this.h = mVar;
        this.i = function1;
        this.j = function12;
        this.k = function13;
        this.l = function0;
        this.m = function02;
        this.n = function03;
        this.o = function04;
        this.p = function14;
        this.q = function05;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(1);
                M5.a(this.r, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, this.l, this.m, this.n, this.o, this.p, this.q, interfaceC0806l, iH);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1);
                O5.a((n) this.r, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, this.l, this.m, this.n, this.o, this.p, this.q, interfaceC0806l, iH2);
                break;
        }
        return Unit.a;
    }
}
