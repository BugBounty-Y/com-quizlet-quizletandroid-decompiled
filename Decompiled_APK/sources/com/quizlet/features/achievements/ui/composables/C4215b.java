package com.quizlet.features.achievements.ui.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3502n4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3625g4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.P;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.achievements.ui.composables.b, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C4215b implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Function0 c;
    public final /* synthetic */ androidx.compose.ui.q d;

    public /* synthetic */ C4215b(Function0 function0, boolean z, androidx.compose.ui.q qVar, int i, int i2) {
        this.a = i2;
        this.c = function0;
        this.b = z;
        this.d = qVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                com.facebook.appevents.i.a(C0776c.H(385), interfaceC0806l, this.d, this.c, this.b);
                break;
            case 1:
                AbstractC3502n4.e(C0776c.H(1), interfaceC0806l, this.d, this.c, this.b);
                break;
            case 2:
                P.c(C0776c.H(1), interfaceC0806l, this.d, this.c, this.b);
                break;
            default:
                AbstractC3625g4.b(C0776c.H(1), interfaceC0806l, this.d, this.c, this.b);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ C4215b(boolean z, Function0 function0, androidx.compose.ui.q qVar, int i, int i2) {
        this.a = i2;
        this.b = z;
        this.c = function0;
        this.d = qVar;
    }
}
