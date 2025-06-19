package androidx.compose.material3.pulltorefresh;

import androidx.compose.ui.graphics.S;
import androidx.compose.ui.graphics.V;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class e extends r implements Function1 {
    public final /* synthetic */ q a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ float c;
    public final /* synthetic */ float d;
    public final /* synthetic */ V e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(q qVar, boolean z, float f, float f2, V v) {
        super(1);
        this.a = qVar;
        this.b = z;
        this.c = f;
        this.d = f2;
        this.e = v;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        S s = (S) obj;
        q qVar = this.a;
        float fFloatValue = ((Number) qVar.a.d()).floatValue();
        float fA = DefinitionKt.NO_Float_VALUE;
        boolean z = fFloatValue > DefinitionKt.NO_Float_VALUE || this.b;
        s.B((((Number) qVar.a.d()).floatValue() * s.m0(this.c)) - androidx.compose.ui.geometry.e.b(s.r));
        if (z) {
            fA = s.s.a() * this.d;
        }
        s.p(fA);
        s.t(this.e);
        s.e(true);
        return Unit.a;
    }
}
