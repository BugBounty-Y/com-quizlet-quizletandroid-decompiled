package com.quizlet.search.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.D0;
import com.quizlet.search.data.term.TermUiModel;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class L implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ TermUiModel b;
    public final /* synthetic */ int c;

    public /* synthetic */ L(TermUiModel termUiModel, int i, int i2) {
        this.a = i2;
        this.b = termUiModel;
        this.c = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).intValue();
        switch (i) {
            case 0:
                D0.b(this.b, interfaceC0806l, C0776c.H(this.c | 1));
                break;
            default:
                D0.d(this.b, interfaceC0806l, C0776c.H(this.c | 1));
                break;
        }
        return Unit.a;
    }
}
