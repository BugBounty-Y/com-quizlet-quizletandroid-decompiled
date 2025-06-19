package com.quizlet.quizletandroid.ui.studymodes.assistant.settings;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.E6;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class n implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ Function1 e;
    public final /* synthetic */ Function1 f;
    public final /* synthetic */ Function1 g;
    public final /* synthetic */ String h;
    public final /* synthetic */ String i;
    public final /* synthetic */ boolean j;
    public final /* synthetic */ androidx.compose.ui.q k;
    public final /* synthetic */ int l;

    public /* synthetic */ n(boolean z, boolean z2, boolean z3, Function1 function1, Function1 function12, Function1 function13, String str, String str2, boolean z4, androidx.compose.ui.q qVar, int i, int i2) {
        this.a = i2;
        this.b = z;
        this.c = z2;
        this.d = z3;
        this.e = function1;
        this.f = function12;
        this.g = function13;
        this.h = str;
        this.i = str2;
        this.j = z4;
        this.k = qVar;
        this.l = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.l | 1);
                boolean z = this.j;
                androidx.compose.ui.q qVar = this.k;
                D6.a(this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, z, qVar, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.l | 1);
                boolean z2 = this.j;
                androidx.compose.ui.q qVar2 = this.k;
                E6.c(this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, z2, qVar2, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }
}
