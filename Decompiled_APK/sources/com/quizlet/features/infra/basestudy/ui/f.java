package com.quizlet.features.infra.basestudy.ui;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.A5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3234p7;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3673m4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.E6;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class f implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ Object b;
    public final /* synthetic */ q c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ InterfaceC4938g e;
    public final /* synthetic */ int f;
    public final /* synthetic */ int g;
    public final /* synthetic */ Object h;

    public /* synthetic */ f(int i, int i2, q qVar, String str, String str2, Function0 function0, boolean z) {
        this.b = str;
        this.h = str2;
        this.d = z;
        this.e = function0;
        this.c = qVar;
        this.f = i;
        this.g = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.f | 1);
                q qVar = this.c;
                int i = this.g;
                A5.c(iH, i, (InterfaceC0806l) obj, qVar, (String) this.b, (String) this.h, (Function0) this.e, this.d);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.f | 1);
                Function0 function0 = (Function0) this.e;
                AbstractC3234p7.d((String) this.b, (androidx.compose.ui.graphics.painter.b) this.h, this.c, this.d, function0, (InterfaceC0806l) obj, iH2, this.g);
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(this.f | 1);
                com.quizlet.qatex.c cVar = (com.quizlet.qatex.c) this.b;
                Function1 function1 = (Function1) this.h;
                AbstractC3673m4.a(cVar, this.c, this.d, (Function0) this.e, function1, (InterfaceC0806l) obj, iH3, this.g);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(this.f | 1);
                String str = (String) this.h;
                q qVar2 = this.c;
                E6.n((String) this.b, this.d, (Function1) this.e, str, qVar2, (InterfaceC0806l) obj, iH4, this.g);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ f(com.quizlet.qatex.c cVar, q qVar, boolean z, Function0 function0, Function1 function1, int i, int i2) {
        this.b = cVar;
        this.c = qVar;
        this.d = z;
        this.e = function0;
        this.h = function1;
        this.f = i;
        this.g = i2;
    }

    public /* synthetic */ f(String str, androidx.compose.ui.graphics.painter.b bVar, q qVar, boolean z, Function0 function0, int i, int i2) {
        this.b = str;
        this.h = bVar;
        this.c = qVar;
        this.d = z;
        this.e = function0;
        this.f = i;
        this.g = i2;
    }

    public /* synthetic */ f(String str, boolean z, Function1 function1, String str2, q qVar, int i, int i2) {
        this.b = str;
        this.d = z;
        this.e = function1;
        this.h = str2;
        this.c = qVar;
        this.f = i;
        this.g = i2;
    }
}
