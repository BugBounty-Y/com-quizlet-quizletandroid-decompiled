package com.quizlet.assembly.compose.cards;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import androidx.compose.ui.text.L;
import com.google.android.gms.internal.mlkit_vision_barcode.A5;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3502n4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3713r5;
import com.quizlet.features.userprofile.data.x;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class i implements Function2 {
    public final /* synthetic */ int a = 2;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ int e;
    public final /* synthetic */ int f;
    public final /* synthetic */ int g;
    public final /* synthetic */ Object h;
    public final /* synthetic */ Object i;

    public /* synthetic */ i(int i, com.quizlet.features.userprofile.navigation.b bVar, q qVar, x xVar, boolean z, Function0 function0, int i2, int i3) {
        this.e = i;
        this.c = bVar;
        this.h = qVar;
        this.d = xVar;
        this.b = z;
        this.i = function0;
        this.f = i2;
        this.g = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.f | 1);
                L l = (L) this.i;
                AbstractC3713r5.a((String) this.c, (String) this.d, this.e, this.b, (q) this.h, l, (InterfaceC0806l) obj, iH, this.g);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.f | 1);
                int i = this.e;
                A5.a(this.b, (com.quizlet.assembly.compose.modals.x) this.h, (String) this.c, (String) this.d, (Function1) this.i, i, (InterfaceC0806l) obj, iH2, this.g);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(this.f | 1);
                Function0 function0 = (Function0) this.i;
                AbstractC3502n4.g(this.e, (com.quizlet.features.userprofile.navigation.b) this.c, (q) this.h, (x) this.d, this.b, function0, (InterfaceC0806l) obj, iH3, this.g);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ i(String str, String str2, int i, boolean z, q qVar, L l, int i2, int i3) {
        this.c = str;
        this.d = str2;
        this.e = i;
        this.b = z;
        this.h = qVar;
        this.i = l;
        this.f = i2;
        this.g = i3;
    }

    public /* synthetic */ i(boolean z, com.quizlet.assembly.compose.modals.x xVar, String str, String str2, Function1 function1, int i, int i2, int i3) {
        this.b = z;
        this.h = xVar;
        this.c = str;
        this.d = str2;
        this.i = function1;
        this.e = i;
        this.f = i2;
        this.g = i3;
    }
}
