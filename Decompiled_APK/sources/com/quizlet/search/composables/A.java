package com.quizlet.search.composables;

import androidx.compose.foundation.layout.z0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.A0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3277v0;
import com.google.android.gms.internal.mlkit_vision_barcode.D0;
import com.quizlet.search.data.term.TermUiModel;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class A implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ A(int i, TermUiModel termUiModel, androidx.compose.ui.q qVar, int i2) {
        this.a = 2;
        this.b = i;
        this.c = termUiModel;
        this.d = qVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        Integer num = (Integer) obj2;
        switch (this.a) {
            case 0:
                num.intValue();
                AbstractC3277v0.j((com.quizlet.assembly.compose.modals.x) this.c, (com.quizlet.search.viewmodels.A) this.d, interfaceC0806l, C0776c.H(this.b | 1));
                break;
            case 1:
                num.getClass();
                A0.d((z0) this.c, (Function0) this.d, interfaceC0806l, C0776c.H(this.b | 1));
                break;
            default:
                num.getClass();
                int iH = C0776c.H(1);
                D0.e(this.b, (TermUiModel) this.c, (androidx.compose.ui.q) this.d, interfaceC0806l, iH);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ A(Object obj, Object obj2, int i, int i2) {
        this.a = i2;
        this.c = obj;
        this.d = obj2;
        this.b = i;
    }
}
