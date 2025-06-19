package com.airbnb.lottie.compose;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class f extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ h b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ f(h hVar, int i) {
        super(0);
        this.a = i;
        this.b = hVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                h hVar = this.b;
                com.airbnb.lottie.h hVar2 = (com.airbnb.lottie.h) ((L0) hVar.i).getValue();
                float f = DefinitionKt.NO_Float_VALUE;
                if (hVar2 != null) {
                    float fFloatValue = ((Number) ((L0) hVar.f).getValue()).floatValue();
                    InterfaceC0773a0 interfaceC0773a0 = hVar.e;
                    if (fFloatValue < DefinitionKt.NO_Float_VALUE) {
                        if (((L0) interfaceC0773a0).getValue() != null) {
                            throw new ClassCastException();
                        }
                    } else {
                        if (((L0) interfaceC0773a0).getValue() != null) {
                            throw new ClassCastException();
                        }
                        f = 1.0f;
                    }
                }
                return Float.valueOf(f);
            case 1:
                h hVar3 = this.b;
                boolean zBooleanValue = ((Boolean) ((L0) hVar3.d).getValue()).booleanValue();
                InterfaceC0773a0 interfaceC0773a02 = hVar3.f;
                return Float.valueOf((zBooleanValue && hVar3.f() % 2 == 0) ? -((Number) ((L0) interfaceC0773a02).getValue()).floatValue() : ((Number) ((L0) interfaceC0773a02).getValue()).floatValue());
            case 2:
                h hVar4 = this.b;
                return Boolean.valueOf(hVar4.f() == ((Number) ((L0) hVar4.c).getValue()).intValue() && ((Number) ((L0) hVar4.k).getValue()).floatValue() == hVar4.e());
            default:
                return Float.valueOf(((Number) this.b.getValue()).floatValue());
        }
    }
}
