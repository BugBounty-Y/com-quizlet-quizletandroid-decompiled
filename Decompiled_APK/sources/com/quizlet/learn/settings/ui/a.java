package com.quizlet.learn.settings.ui;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D6;
import com.quizlet.learn.settings.data.WrittenQuestionGradingOption;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlinx.collections.immutable.c;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ c b;
    public final /* synthetic */ WrittenQuestionGradingOption c;
    public final /* synthetic */ Function1 d;
    public final /* synthetic */ q e;
    public final /* synthetic */ int f;

    public /* synthetic */ a(c cVar, WrittenQuestionGradingOption writtenQuestionGradingOption, Function1 function1, q qVar, int i, int i2) {
        this.a = i2;
        this.b = cVar;
        this.c = writtenQuestionGradingOption;
        this.d = function1;
        this.e = qVar;
        this.f = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.f | 1);
                Function1 function1 = this.d;
                q qVar = this.e;
                b.a(this.b, this.c, function1, qVar, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.f | 1);
                Function1 function12 = this.d;
                q qVar2 = this.e;
                D6.h(this.b, this.c, function12, qVar2, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }
}
