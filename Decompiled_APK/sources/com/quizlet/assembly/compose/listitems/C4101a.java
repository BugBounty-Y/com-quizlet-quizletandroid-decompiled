package com.quizlet.assembly.compose.listitems;

import androidx.compose.foundation.layout.A0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_document_scanner.B5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D5;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.assembly.compose.listitems.a, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C4101a implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.runtime.internal.d b;
    public final /* synthetic */ androidx.compose.runtime.internal.d c;
    public final /* synthetic */ androidx.compose.runtime.internal.d d;
    public final /* synthetic */ androidx.compose.ui.q e;
    public final /* synthetic */ boolean f;
    public final /* synthetic */ androidx.compose.runtime.internal.d g;
    public final /* synthetic */ boolean h;
    public final /* synthetic */ z i;
    public final /* synthetic */ A0 j;
    public final /* synthetic */ float k;
    public final /* synthetic */ float l;
    public final /* synthetic */ Function0 m;
    public final /* synthetic */ int n;
    public final /* synthetic */ int o;
    public final /* synthetic */ int p;

    public /* synthetic */ C4101a(androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, androidx.compose.ui.q qVar, boolean z, androidx.compose.runtime.internal.d dVar4, boolean z2, z zVar, A0 a0, float f, float f2, Function0 function0, int i, int i2, int i3, int i4) {
        this.a = i4;
        this.b = dVar;
        this.c = dVar2;
        this.d = dVar3;
        this.e = qVar;
        this.f = z;
        this.g = dVar4;
        this.h = z2;
        this.i = zVar;
        this.j = a0;
        this.k = f;
        this.l = f2;
        this.m = function0;
        this.n = i;
        this.o = i2;
        this.p = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.n | 1);
                int iH2 = C0776c.H(this.o);
                B5.b(this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, this.l, this.m, interfaceC0806l, iH, iH2, this.p);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(this.n | 1);
                int iH4 = C0776c.H(this.o);
                D5.a(this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, this.l, this.m, interfaceC0806l, iH3, iH4, this.p);
                break;
        }
        return Unit.a;
    }
}
