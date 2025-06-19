package com.quizlet.quizletandroid.ui.studymodes.assistant.settings;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.E6;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class m implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Function0 c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ boolean e;
    public final /* synthetic */ boolean f;
    public final /* synthetic */ Function1 g;
    public final /* synthetic */ Function1 h;
    public final /* synthetic */ Function1 i;
    public final /* synthetic */ androidx.compose.ui.q j;
    public final /* synthetic */ int k;

    public /* synthetic */ m(boolean z, Function0 function0, boolean z2, boolean z3, boolean z4, Function1 function1, Function1 function12, Function1 function13, androidx.compose.ui.q qVar, int i, int i2) {
        this.a = i2;
        this.b = z;
        this.c = function0;
        this.d = z2;
        this.e = z3;
        this.f = z4;
        this.g = function1;
        this.h = function12;
        this.i = function13;
        this.j = qVar;
        this.k = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.k | 1);
                Function1 function1 = this.i;
                androidx.compose.ui.q qVar = this.j;
                D6.j(this.b, this.c, this.d, this.e, this.f, this.g, this.h, function1, qVar, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.k | 1);
                Function1 function12 = this.i;
                androidx.compose.ui.q qVar2 = this.j;
                E6.l(this.b, this.c, this.d, this.e, this.f, this.g, this.h, function12, qVar2, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }
}
