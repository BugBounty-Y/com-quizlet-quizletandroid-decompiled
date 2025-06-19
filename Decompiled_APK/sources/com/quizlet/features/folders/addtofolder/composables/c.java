package com.quizlet.features.folders.addtofolder.composables;

import androidx.compose.foundation.layout.z0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.B0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3736u4;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements Function2 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ String b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ Function1 d;
    public final /* synthetic */ int e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ Object h;
    public final /* synthetic */ Object i;
    public final /* synthetic */ Object j;

    public /* synthetic */ c(z0 z0Var, String str, String str2, boolean z, Function1 function1, Function1 function12, Function1 function13, com.quizlet.quizletandroid.ui.classcreation.data.b bVar, int i) {
        this.f = z0Var;
        this.b = str;
        this.g = str2;
        this.c = z;
        this.d = function1;
        this.h = function12;
        this.i = function13;
        this.j = bVar;
        this.e = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.e | 1);
                String str = this.b;
                Function1 function1 = this.d;
                B0.c((kotlinx.collections.immutable.b) this.f, (com.quizlet.features.folders.addtofolder.data.o) this.g, (com.quizlet.features.folders.addtofolder.data.r) this.h, (com.quizlet.features.folders.addtofolder.data.t) this.i, this.c, (androidx.compose.ui.q) this.j, str, function1, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.e | 1);
                Function1 function12 = (Function1) this.i;
                com.quizlet.quizletandroid.ui.classcreation.data.b bVar = (com.quizlet.quizletandroid.ui.classcreation.data.b) this.j;
                AbstractC3736u4.b((z0) this.f, this.b, (String) this.g, this.c, this.d, (Function1) this.h, function12, bVar, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ c(kotlinx.collections.immutable.b bVar, com.quizlet.features.folders.addtofolder.data.o oVar, com.quizlet.features.folders.addtofolder.data.r rVar, com.quizlet.features.folders.addtofolder.data.t tVar, boolean z, androidx.compose.ui.q qVar, String str, Function1 function1, int i) {
        this.f = bVar;
        this.g = oVar;
        this.h = rVar;
        this.i = tVar;
        this.c = z;
        this.j = qVar;
        this.b = str;
        this.d = function1;
        this.e = i;
    }
}
