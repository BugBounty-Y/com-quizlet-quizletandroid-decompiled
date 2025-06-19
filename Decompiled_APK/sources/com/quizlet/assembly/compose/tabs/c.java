package com.quizlet.assembly.compose.tabs;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.n;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3275u6;
import com.google.android.gms.internal.mlkit_vision_camera.N1;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3561x4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3627g6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.E6;
import com.quizlet.learn.data.onboarding.m;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements Function2 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ int e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;

    public /* synthetic */ c(n nVar, boolean z, boolean z2, Function0 function0, Function0 function02, int i) {
        this.f = nVar;
        this.b = z;
        this.c = z2;
        this.d = function0;
        this.g = function02;
        this.e = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(1);
                Function0 function0 = (Function0) this.d;
                AbstractC3627g6.b((String) this.f, this.b, (q) this.g, this.c, function0, (InterfaceC0806l) obj, iH, this.e);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.e | 1);
                Function0 function02 = (Function0) this.d;
                Function0 function03 = (Function0) this.g;
                AbstractC3275u6.a((n) this.f, this.b, this.c, function02, function03, (InterfaceC0806l) obj, iH2);
                break;
            case 2:
                ((Integer) obj2).intValue();
                N1.e((String) this.f, this.b, this.c, (Function1) this.g, (String) this.d, (InterfaceC0806l) obj, C0776c.H(this.e | 1));
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(this.e | 1);
                m mVar = (m) this.f;
                boolean z = this.c;
                Function0 function04 = (Function0) this.d;
                AbstractC3561x4.a(mVar, (q) this.g, this.b, z, function04, (InterfaceC0806l) obj, iH3);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(this.e | 1);
                Function1 function1 = (Function1) this.g;
                n nVar = (n) this.d;
                E6.f(this.b, this.c, (Function1) this.f, function1, nVar, (InterfaceC0806l) obj, iH4);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ c(m mVar, q qVar, boolean z, boolean z2, Function0 function0, int i) {
        this.f = mVar;
        this.g = qVar;
        this.b = z;
        this.c = z2;
        this.d = function0;
        this.e = i;
    }

    public /* synthetic */ c(String str, boolean z, q qVar, boolean z2, Function0 function0, int i, int i2) {
        this.f = str;
        this.b = z;
        this.g = qVar;
        this.c = z2;
        this.d = function0;
        this.e = i2;
    }

    public /* synthetic */ c(String str, boolean z, boolean z2, Function1 function1, String str2, int i) {
        this.f = str;
        this.b = z;
        this.c = z2;
        this.g = function1;
        this.d = str2;
        this.e = i;
    }

    public /* synthetic */ c(boolean z, boolean z2, Function1 function1, Function1 function12, n nVar, int i) {
        this.b = z;
        this.c = z2;
        this.f = function1;
        this.g = function12;
        this.d = nVar;
        this.e = i;
    }
}
