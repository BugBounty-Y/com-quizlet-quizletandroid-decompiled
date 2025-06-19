package com.quizlet.login.emailsent.ui;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_document_scanner.K;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ q c;
    public final /* synthetic */ Function0 d;

    public /* synthetic */ a(q qVar, String str, Function0 function0, int i, int i2) {
        this.a = i2;
        this.b = str;
        this.c = qVar;
        this.d = function0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                K.b(C0776c.H(1), interfaceC0806l, this.c, this.b, this.d);
                break;
            default:
                K.a(C0776c.H(1), interfaceC0806l, this.c, this.b, this.d);
                break;
        }
        return Unit.a;
    }
}
