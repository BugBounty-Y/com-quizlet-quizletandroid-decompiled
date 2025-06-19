package com.quizlet.assembly.compose.menu;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_document_scanner.F5;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class b implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ s c;
    public final /* synthetic */ Function1 d;
    public final /* synthetic */ long e;
    public final /* synthetic */ Function0 f;
    public final /* synthetic */ int g;

    public /* synthetic */ b(androidx.compose.ui.q qVar, s sVar, Function1 function1, long j, Function0 function0, int i, int i2) {
        this.a = i2;
        this.b = qVar;
        this.c = sVar;
        this.d = function1;
        this.e = j;
        this.f = function0;
        this.g = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.g | 1);
                long j = this.e;
                Function0 function0 = this.f;
                F5.a(this.b, this.c, this.d, j, function0, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.g | 1);
                s sVar = this.c;
                long j2 = this.e;
                Function0 function02 = this.f;
                F5.c(this.b, sVar, this.d, j2, function02, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }
}
