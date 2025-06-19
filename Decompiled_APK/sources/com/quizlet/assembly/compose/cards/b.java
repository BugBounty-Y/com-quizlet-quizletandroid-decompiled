package com.quizlet.assembly.compose.cards;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.n;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3579a6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3650j5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3682n5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3698p5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class b implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ InterfaceC4938g d;
    public final /* synthetic */ int e;
    public final /* synthetic */ int f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ Object h;
    public final /* synthetic */ Object i;

    public /* synthetic */ b(int i, int i2, int i3, q qVar, String str, String str2, Function0 function0, Function1 function1) {
        this.a = 4;
        this.g = str;
        this.h = function1;
        this.d = function0;
        this.i = qVar;
        this.b = i;
        this.c = str2;
        this.e = i2;
        this.f = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.e | 1);
                Function0 function0 = (Function0) this.d;
                AbstractC3650j5.a((com.quizlet.ui.models.content.carditem.a) this.g, (n) this.h, this.b, (Function2) this.i, (com.quizlet.ui.compose.util.a) this.c, function0, (InterfaceC0806l) obj, iH, this.f);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.e | 1);
                Function0 function02 = (Function0) this.d;
                AbstractC3682n5.a((com.quizlet.ui.models.content.carditem.e) this.g, (q) this.h, this.b, (kotlin.jvm.functions.c) this.i, (com.quizlet.ui.compose.util.a) this.c, function02, (InterfaceC0806l) obj, iH2, this.f);
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(this.e | 1);
                Function0 function03 = (Function0) this.d;
                AbstractC3698p5.a((com.quizlet.ui.models.content.carditem.g) this.g, (q) this.h, this.b, (kotlin.jvm.functions.c) this.i, (com.quizlet.ui.compose.util.a) this.c, function03, (InterfaceC0806l) obj, iH3, this.f);
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(this.e | 1);
                int i = this.b;
                AbstractC3579a6.e((String) this.g, (q) this.h, (String) this.i, (androidx.compose.runtime.internal.d) this.c, (androidx.compose.runtime.internal.d) this.d, i, (InterfaceC0806l) obj, iH4, this.f);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(this.f | 1);
                String str = (String) this.c;
                int i2 = this.e;
                String str2 = (String) this.g;
                Function1 function1 = (Function1) this.h;
                Function0 function04 = (Function0) this.d;
                D.b(this.b, i2, iH5, (InterfaceC0806l) obj, (q) this.i, str2, str, function04, function1);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ b(Object obj, q qVar, int i, InterfaceC4938g interfaceC4938g, com.quizlet.ui.compose.util.a aVar, Function0 function0, int i2, int i3, int i4) {
        this.a = i4;
        this.g = obj;
        this.h = qVar;
        this.b = i;
        this.i = interfaceC4938g;
        this.c = aVar;
        this.d = function0;
        this.e = i2;
        this.f = i3;
    }

    public /* synthetic */ b(String str, q qVar, String str2, androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, int i, int i2, int i3) {
        this.a = 3;
        this.g = str;
        this.h = qVar;
        this.i = str2;
        this.c = dVar;
        this.d = dVar2;
        this.b = i;
        this.e = i2;
        this.f = i3;
    }
}
