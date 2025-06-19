package com.quizlet.features.infra.basestudy.ui;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.B5;
import com.quizlet.ui.compose.AbstractC4827u;
import com.quizlet.ui.compose.d0;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class j implements Function2 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ String b;
    public final /* synthetic */ q c;
    public final /* synthetic */ String d;
    public final /* synthetic */ boolean e;
    public final /* synthetic */ int f;
    public final /* synthetic */ Function0 g;
    public final /* synthetic */ int h;
    public final /* synthetic */ int i;
    public final /* synthetic */ Object j;
    public final /* synthetic */ Object k;

    public /* synthetic */ j(String str, q qVar, String str2, d0 d0Var, boolean z, int i, androidx.compose.runtime.internal.d dVar, Function0 function0, int i2, int i3) {
        this.b = str;
        this.c = qVar;
        this.d = str2;
        this.j = d0Var;
        this.e = z;
        this.f = i;
        this.k = dVar;
        this.g = function0;
        this.h = i2;
        this.i = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.h | 1);
                Function0 function0 = this.g;
                B5.a(this.b, this.d, (String) this.j, this.f, this.e, (String) this.k, this.c, function0, (InterfaceC0806l) obj, iH, this.i);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.h | 1);
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) this.k;
                Function0 function02 = this.g;
                AbstractC4827u.a(this.b, this.c, this.d, (d0) this.j, this.e, this.f, dVar, function02, (InterfaceC0806l) obj, iH2, this.i);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ j(String str, String str2, String str3, int i, boolean z, String str4, q qVar, Function0 function0, int i2, int i3) {
        this.b = str;
        this.d = str2;
        this.j = str3;
        this.f = i;
        this.e = z;
        this.k = str4;
        this.c = qVar;
        this.g = function0;
        this.h = i2;
        this.i = i3;
    }
}
