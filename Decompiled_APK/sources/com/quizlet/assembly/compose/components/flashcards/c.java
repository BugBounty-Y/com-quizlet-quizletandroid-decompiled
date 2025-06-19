package com.quizlet.assembly.compose.components.flashcards;

import androidx.compose.foundation.C0555x;
import androidx.compose.foundation.interaction.l;
import androidx.compose.foundation.layout.A0;
import androidx.compose.foundation.layout.InterfaceC0388h;
import androidx.compose.foundation.layout.InterfaceC0394k;
import androidx.compose.foundation.lazy.grid.A;
import androidx.compose.material3.Y;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3266t5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3721s5;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ q b;
    public final /* synthetic */ long c;
    public final /* synthetic */ int d;
    public final /* synthetic */ androidx.compose.runtime.internal.d e;
    public final /* synthetic */ androidx.compose.runtime.internal.d f;
    public final /* synthetic */ int g;
    public final /* synthetic */ int h;
    public final /* synthetic */ Object i;
    public final /* synthetic */ Object j;
    public final /* synthetic */ Object k;
    public final /* synthetic */ Object l;
    public final /* synthetic */ Object m;
    public final /* synthetic */ InterfaceC4938g n;

    public /* synthetic */ c(b bVar, q qVar, d dVar, l lVar, long j, C0555x c0555x, Y y, Function1 function1, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, int i, int i2, int i3) {
        this.i = bVar;
        this.b = qVar;
        this.j = dVar;
        this.k = lVar;
        this.c = j;
        this.l = c0555x;
        this.m = y;
        this.n = function1;
        this.e = dVar2;
        this.f = dVar3;
        this.d = i;
        this.g = i2;
        this.h = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.g | 1);
                AbstractC3721s5.a((b) this.i, this.b, (d) this.j, (l) this.k, this.c, (C0555x) this.l, (Y) this.m, (Function1) this.n, this.e, this.f, this.d, interfaceC0806l, iH, this.h);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.g | 1);
                AbstractC3266t5.b((Function0) this.i, this.b, this.c, this.d, (A0) this.j, (InterfaceC0394k) this.k, (InterfaceC0388h) this.l, (A) this.m, this.e, this.f, (Function2) this.n, interfaceC0806l, iH2, this.h);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ c(Function0 function0, q qVar, long j, int i, A0 a0, InterfaceC0394k interfaceC0394k, InterfaceC0388h interfaceC0388h, A a, androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, Function2 function2, int i2, int i3) {
        this.i = function0;
        this.b = qVar;
        this.c = j;
        this.d = i;
        this.j = a0;
        this.k = interfaceC0394k;
        this.l = interfaceC0388h;
        this.m = a;
        this.e = dVar;
        this.f = dVar2;
        this.n = function2;
        this.g = i2;
        this.h = i3;
    }
}
