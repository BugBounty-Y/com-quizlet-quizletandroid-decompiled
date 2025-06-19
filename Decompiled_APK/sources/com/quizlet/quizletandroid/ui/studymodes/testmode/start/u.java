package com.quizlet.quizletandroid.ui.studymodes.testmode.start;

import com.quizlet.generated.enums.O1;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final /* synthetic */ class u implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ A b;

    public /* synthetic */ u(A a, int i) {
        this.a = i;
        this.b = a;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        int i = this.a;
        boolean zBooleanValue = ((Boolean) obj).booleanValue();
        switch (i) {
            case 0:
                this.b.E(O1.LOCATION, zBooleanValue);
                break;
            case 1:
                this.b.F(O1.LOCATION, zBooleanValue);
                break;
            case 2:
                this.b.E(O1.WORD, zBooleanValue);
                break;
            case 3:
                this.b.E(O1.DEFINITION, zBooleanValue);
                break;
            case 4:
                this.b.F(O1.WORD, zBooleanValue);
                break;
            case 5:
                this.b.F(O1.DEFINITION, zBooleanValue);
                break;
            case 6:
                this.b.F(O1.LOCATION, zBooleanValue);
                break;
            default:
                this.b.E(O1.LOCATION, zBooleanValue);
                break;
        }
        return Unit.a;
    }
}
