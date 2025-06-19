package com.quizlet.features.infra.folder.tag.composable;

import androidx.compose.material3.O3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3267t6;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class i implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.features.infra.folder.tag.screenstates.k b;
    public final /* synthetic */ O3 c;
    public final /* synthetic */ q d;
    public final /* synthetic */ Function0 e;
    public final /* synthetic */ Function1 f;

    public /* synthetic */ i(com.quizlet.features.infra.folder.tag.screenstates.k kVar, O3 o3, q qVar, Function0 function0, Function1 function1, int i, int i2) {
        this.a = i2;
        this.b = kVar;
        this.c = o3;
        this.d = qVar;
        this.e = function0;
        this.f = function1;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(1);
                Function0 function0 = this.e;
                Function1 function1 = this.f;
                AbstractC3267t6.d(this.b, this.c, this.d, function0, function1, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1);
                Function0 function02 = this.e;
                Function1 function12 = this.f;
                AbstractC3267t6.e(this.b, this.c, this.d, function02, function12, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }
}
