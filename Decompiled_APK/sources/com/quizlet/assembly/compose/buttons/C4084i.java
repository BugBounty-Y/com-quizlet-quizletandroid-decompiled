package com.quizlet.assembly.compose.buttons;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_document_scanner.T4;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.assembly.compose.buttons.i, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C4084i implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ androidx.compose.ui.q c;

    public /* synthetic */ C4084i(int i, int i2, long j, androidx.compose.ui.q qVar) {
        this.a = i2;
        this.b = j;
        this.c = qVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                T4.d(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            default:
                com.google.android.exoplayer2.drm.b.d(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
        }
        return Unit.a;
    }
}
