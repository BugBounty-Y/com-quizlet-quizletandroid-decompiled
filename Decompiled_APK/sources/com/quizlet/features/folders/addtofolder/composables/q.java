package com.quizlet.features.folders.addtofolder.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.A5;
import com.google.android.gms.internal.mlkit_vision_barcode.D0;
import com.google.android.gms.internal.mlkit_vision_barcode.z7;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3423a3;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3502n4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3578a5;
import com.quizlet.assembly.compose.modals.x;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class q implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ int e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;

    public /* synthetic */ q(int i, int i2, androidx.compose.ui.q qVar, String str, String str2, Function0 function0, boolean z) {
        this.a = 2;
        this.c = str;
        this.f = str2;
        this.b = z;
        this.d = qVar;
        this.g = function0;
        this.e = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.e | 1);
                Function1 function1 = (Function1) this.d;
                Function0 function0 = (Function0) this.g;
                D0.a((androidx.compose.ui.n) this.f, (String) this.c, this.b, function1, function0, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.e | 1);
                String str = (String) this.g;
                Function1 function12 = (Function1) this.d;
                A5.b(this.b, (x) this.f, (String) this.c, str, function12, (InterfaceC0806l) obj, iH2);
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(1);
                Function0 function02 = (Function0) this.g;
                int i = this.e;
                z7.d(iH3, i, (InterfaceC0806l) obj, (androidx.compose.ui.q) this.d, (String) this.c, (String) this.f, function02, this.b);
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(this.e | 1);
                AbstractC3423a3.c(iH4, (InterfaceC0806l) obj, (com.quizlet.qutils.string.g) this.f, (String) this.c, (Function0) this.g, (Function1) this.d, this.b);
                break;
            case 4:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(this.e | 1);
                Function0 function03 = (Function0) this.g;
                Function0 function04 = (Function0) this.d;
                AbstractC3502n4.c((androidx.compose.ui.q) this.f, this.b, (Integer) this.c, function03, function04, (InterfaceC0806l) obj, iH5);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH6 = C0776c.H(this.e | 1);
                Function1 function13 = (Function1) this.c;
                boolean z = this.b;
                AbstractC3578a5.b((Function0) this.g, (Function1) this.d, (Function0) this.f, function13, z, (InterfaceC0806l) obj, iH6);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ q(androidx.compose.ui.n nVar, String str, boolean z, Function1 function1, Function0 function0, int i) {
        this.a = 0;
        this.f = nVar;
        this.c = str;
        this.b = z;
        this.d = function1;
        this.g = function0;
        this.e = i;
    }

    public /* synthetic */ q(androidx.compose.ui.q qVar, boolean z, Integer num, Function0 function0, Function0 function02, int i) {
        this.a = 4;
        this.f = qVar;
        this.b = z;
        this.c = num;
        this.g = function0;
        this.d = function02;
        this.e = i;
    }

    public /* synthetic */ q(Function0 function0, Function1 function1, Function0 function02, Function1 function12, boolean z, int i) {
        this.a = 5;
        this.g = function0;
        this.d = function1;
        this.f = function02;
        this.c = function12;
        this.b = z;
        this.e = i;
    }

    public /* synthetic */ q(boolean z, Object obj, String str, Object obj2, Function1 function1, int i, int i2) {
        this.a = i2;
        this.b = z;
        this.f = obj;
        this.c = str;
        this.g = obj2;
        this.d = function1;
        this.e = i;
    }
}
