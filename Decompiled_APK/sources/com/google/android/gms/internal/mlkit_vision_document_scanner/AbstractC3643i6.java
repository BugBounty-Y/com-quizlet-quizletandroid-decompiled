package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3643i6;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.i6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3643i6 {
    public static final /* synthetic */ int a = 0;

    public static final void a(final androidx.compose.ui.graphics.painter.b painter, final String str, androidx.compose.ui.q qVar, float f, InterfaceC0806l interfaceC0806l, final int i, final int i2) {
        int i3;
        final androidx.compose.ui.q qVar2;
        final float f2;
        Intrinsics.checkNotNullParameter(painter, "painter");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1087968872);
        int i4 = (c0814p.h(painter) ? 4 : 2) | i | (c0814p.f(str) ? 32 : 16);
        int i5 = i4 | 384;
        int i6 = i2 & 8;
        if (i6 != 0) {
            i3 = i4 | 3456;
        } else {
            i3 = i5 | (c0814p.c(f) ? 2048 : 1024);
        }
        if ((i3 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
            f2 = f;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            float f3 = i6 != 0 ? com.quizlet.assembly.compose.tags.g.b : f;
            androidx.compose.material3.D1.a(painter, str, androidx.compose.foundation.layout.K0.k(nVar, f3), 0L, c0814p, i3 & 126, 8);
            qVar2 = nVar;
            f2 = f3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(str, qVar2, f2, i, i2) { // from class: com.quizlet.assembly.compose.tags.h
                public final /* synthetic */ String b;
                public final /* synthetic */ q c;
                public final /* synthetic */ float d;
                public final /* synthetic */ int e;

                {
                    this.e = i2;
                }

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(1);
                    float f4 = this.d;
                    int i7 = this.e;
                    AbstractC3643i6.a(this.a, this.b, this.c, f4, (InterfaceC0806l) obj, iH, i7);
                    return Unit.a;
                }
            };
        }
    }
}
