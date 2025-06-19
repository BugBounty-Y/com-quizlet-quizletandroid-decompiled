package com.quizlet.assembly.compose.listitems;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3634h5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.C5;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class m implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ InterfaceC4938g f;
    public final /* synthetic */ boolean g;
    public final /* synthetic */ Object h;
    public final /* synthetic */ int i;
    public final /* synthetic */ int j;
    public final /* synthetic */ Object k;

    public /* synthetic */ m(Object obj, androidx.compose.ui.q qVar, boolean z, Integer num, String str, Function0 function0, boolean z2, Function0 function02, int i, int i2, int i3) {
        this.a = i3;
        this.k = obj;
        this.b = qVar;
        this.c = z;
        this.d = num;
        this.e = str;
        this.f = function0;
        this.g = z2;
        this.h = function02;
        this.i = i;
        this.j = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.i | 1);
                Function0 function0 = (Function0) this.h;
                C5.d((com.quizlet.ui.models.content.listitem.c) this.k, (androidx.compose.ui.q) this.b, this.c, (Integer) this.d, (String) this.e, (Function0) this.f, this.g, function0, (InterfaceC0806l) obj, iH, this.j);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.i | 1);
                Function0 function02 = (Function0) this.h;
                C5.o((com.quizlet.ui.models.content.listitem.p) this.k, (androidx.compose.ui.q) this.b, this.c, (Integer) this.d, (String) this.e, (Function0) this.f, this.g, function02, (InterfaceC0806l) obj, iH2, this.j);
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(this.i | 1);
                Function0 function03 = (Function0) this.h;
                C5.q((com.quizlet.ui.models.content.listitem.q) this.k, (androidx.compose.ui.q) this.b, this.c, (Integer) this.d, (String) this.e, (Function0) this.f, this.g, function03, (InterfaceC0806l) obj, iH3, this.j);
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(this.i | 1);
                Function0 function04 = (Function0) this.h;
                C5.f((com.quizlet.ui.models.content.listitem.d) this.k, (androidx.compose.ui.q) this.b, this.c, (Integer) this.d, (String) this.e, (Function0) this.f, this.g, function04, (InterfaceC0806l) obj, iH4, this.j);
                break;
            case 4:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(this.i | 1);
                Function0 function05 = (Function0) this.h;
                C5.h((com.quizlet.ui.models.content.listitem.e) this.k, (androidx.compose.ui.q) this.b, this.c, (Integer) this.d, (String) this.e, (Function0) this.f, this.g, function05, (InterfaceC0806l) obj, iH5, this.j);
                break;
            case 5:
                ((Integer) obj2).getClass();
                int iH6 = C0776c.H(this.i | 1);
                Function0 function06 = (Function0) this.h;
                C5.k((com.quizlet.ui.models.content.listitem.f) this.k, (androidx.compose.ui.q) this.b, this.c, (Integer) this.d, (String) this.e, (Function0) this.f, this.g, function06, (InterfaceC0806l) obj, iH6, this.j);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH7 = C0776c.H(this.i | 1);
                boolean z = this.g;
                AbstractC3634h5.a((kotlinx.collections.immutable.b) this.k, this.c, (Function1) this.b, (Function1) this.d, (Function1) this.e, (Function1) this.f, (com.quizlet.quizletandroid.util.o) this.h, z, (InterfaceC0806l) obj, iH7, this.j);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ m(kotlinx.collections.immutable.b bVar, boolean z, Function1 function1, Function1 function12, Function1 function13, Function1 function14, com.quizlet.quizletandroid.util.o oVar, boolean z2, int i, int i2) {
        this.a = 6;
        this.k = bVar;
        this.c = z;
        this.b = function1;
        this.d = function12;
        this.e = function13;
        this.f = function14;
        this.h = oVar;
        this.g = z2;
        this.i = i;
        this.j = i2;
    }
}
