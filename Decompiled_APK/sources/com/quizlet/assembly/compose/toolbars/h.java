package com.quizlet.assembly.compose.toolbars;

import androidx.compose.foundation.layout.C0374a;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3691o6;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class h implements Function2 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ androidx.compose.runtime.internal.d b;
    public final /* synthetic */ q c;
    public final /* synthetic */ long d;
    public final /* synthetic */ long e;
    public final /* synthetic */ long f;
    public final /* synthetic */ C0374a g;
    public final /* synthetic */ androidx.compose.runtime.internal.d h;
    public final /* synthetic */ int i;
    public final /* synthetic */ int j;
    public final /* synthetic */ Object k;

    public /* synthetic */ h(androidx.compose.runtime.internal.d dVar, q qVar, long j, long j2, long j3, C0374a c0374a, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, int i, int i2) {
        this.b = dVar;
        this.c = qVar;
        this.d = j;
        this.e = j2;
        this.f = j3;
        this.g = c0374a;
        this.h = dVar2;
        this.k = dVar3;
        this.i = i;
        this.j = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.i | 1);
                AbstractC3691o6.a(this.c, this.d, this.e, this.f, (String) this.k, this.b, this.h, this.g, interfaceC0806l, iH, this.j);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.i | 1);
                AbstractC3691o6.b(this.b, this.c, this.d, this.e, this.f, this.g, this.h, (androidx.compose.runtime.internal.d) this.k, interfaceC0806l, iH2, this.j);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ h(q qVar, long j, long j2, long j3, String str, androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, C0374a c0374a, int i, int i2) {
        this.c = qVar;
        this.d = j;
        this.e = j2;
        this.f = j3;
        this.k = str;
        this.b = dVar;
        this.h = dVar2;
        this.g = c0374a;
        this.i = i;
        this.j = i2;
    }
}
