package androidx.compose.material3.internal;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Pair;
import kotlin.jvm.functions.Function0;

/* renamed from: androidx.compose.material3.internal.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0648l extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.work.impl.model.t b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0648l(androidx.work.impl.model.t tVar, int i) {
        super(0);
        this.a = i;
        this.b = tVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return this.b.h();
            case 1:
                androidx.work.impl.model.t tVar = this.b;
                return new Pair(tVar.h(), ((androidx.compose.runtime.E) tVar.h).getValue());
            case 2:
                androidx.work.impl.model.t tVar2 = this.b;
                Object value = ((L0) ((InterfaceC0773a0) tVar2.l)).getValue();
                if (value != null) {
                    return value;
                }
                float fK = tVar2.k();
                boolean zIsNaN = Float.isNaN(fK);
                InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) tVar2.g;
                if (zIsNaN) {
                    return ((L0) interfaceC0773a0).getValue();
                }
                Object value2 = ((L0) interfaceC0773a0).getValue();
                F fH = tVar2.h();
                float fC = fH.c(value2);
                if (fC != fK && !Float.isNaN(fC)) {
                    if (fC < fK) {
                        Object objB = fH.b(fK, true);
                        if (objB != null) {
                            return objB;
                        }
                    } else {
                        Object objB2 = fH.b(fK, false);
                        if (objB2 != null) {
                            return objB2;
                        }
                    }
                }
                return value2;
            case 3:
                androidx.work.impl.model.t tVar3 = this.b;
                float fC2 = tVar3.h().c(((L0) ((InterfaceC0773a0) tVar3.g)).getValue());
                float fC3 = tVar3.h().c(((androidx.compose.runtime.E) tVar3.i).getValue()) - fC2;
                float fAbs = Math.abs(fC3);
                float f = 1.0f;
                if (!Float.isNaN(fAbs) && fAbs > 1.0E-6f) {
                    float fS = (tVar3.s() - fC2) / fC3;
                    if (fS < 1.0E-6f) {
                        f = DefinitionKt.NO_Float_VALUE;
                    } else if (fS <= 0.999999f) {
                        f = fS;
                    }
                }
                return Float.valueOf(f);
            default:
                androidx.work.impl.model.t tVar4 = this.b;
                Object value3 = ((L0) ((InterfaceC0773a0) tVar4.l)).getValue();
                if (value3 != null) {
                    return value3;
                }
                float fK2 = tVar4.k();
                boolean zIsNaN2 = Float.isNaN(fK2);
                InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) tVar4.g;
                return !zIsNaN2 ? tVar4.e(fK2, DefinitionKt.NO_Float_VALUE, ((L0) interfaceC0773a02).getValue()) : ((L0) interfaceC0773a02).getValue();
        }
    }
}
