package androidx.compose.material;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Pair;
import kotlin.jvm.functions.Function0;

/* renamed from: androidx.compose.material.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0567j extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ C0575s b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0567j(C0575s c0575s, int i) {
        super(0);
        this.a = i;
        this.b = c0575s;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return this.b.d();
            case 1:
                C0575s c0575s = this.b;
                return new Pair(c0575s.d(), c0575s.g.getValue());
            case 2:
                C0575s c0575s2 = this.b;
                Object value = ((L0) c0575s2.k).getValue();
                if (value != null) {
                    return value;
                }
                float fE = c0575s2.e();
                boolean zIsNaN = Float.isNaN(fE);
                InterfaceC0773a0 interfaceC0773a0 = c0575s2.f;
                if (zIsNaN) {
                    return ((L0) interfaceC0773a0).getValue();
                }
                Object value2 = ((L0) interfaceC0773a0).getValue();
                G gD = c0575s2.d();
                float fC = gD.c(value2);
                if (fC != fE && !Float.isNaN(fC)) {
                    if (fC < fE) {
                        Object objB = gD.b(fE, true);
                        if (objB != null) {
                            return objB;
                        }
                    } else {
                        Object objB2 = gD.b(fE, false);
                        if (objB2 != null) {
                            return objB2;
                        }
                    }
                }
                return value2;
            case 3:
                C0575s c0575s3 = this.b;
                float fC2 = c0575s3.d().c(((L0) c0575s3.f).getValue());
                float fC3 = c0575s3.d().c(c0575s3.h.getValue()) - fC2;
                float fAbs = Math.abs(fC3);
                float f = 1.0f;
                if (!Float.isNaN(fAbs) && fAbs > 1.0E-6f) {
                    float fG = (c0575s3.g() - fC2) / fC3;
                    if (fG < 1.0E-6f) {
                        f = DefinitionKt.NO_Float_VALUE;
                    } else if (fG <= 0.999999f) {
                        f = fG;
                    }
                }
                return Float.valueOf(f);
            default:
                C0575s c0575s4 = this.b;
                Object value3 = ((L0) c0575s4.k).getValue();
                if (value3 != null) {
                    return value3;
                }
                float fE2 = c0575s4.e();
                boolean zIsNaN2 = Float.isNaN(fE2);
                InterfaceC0773a0 interfaceC0773a02 = c0575s4.f;
                return !zIsNaN2 ? c0575s4.c(fE2, DefinitionKt.NO_Float_VALUE, ((L0) interfaceC0773a02).getValue()) : ((L0) interfaceC0773a02).getValue();
        }
    }
}
