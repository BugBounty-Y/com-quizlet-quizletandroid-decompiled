package androidx.compose.ui.draw;

import androidx.compose.ui.graphics.C0856p;
import androidx.compose.ui.graphics.F;
import androidx.compose.ui.graphics.S;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class a extends r implements Function1 {
    public final /* synthetic */ float a;
    public final /* synthetic */ float b;
    public final /* synthetic */ int c;
    public final /* synthetic */ com.quizlet.shared.usecase.folderstudymaterials.d d;
    public final /* synthetic */ boolean e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(float f, float f2, int i, com.quizlet.shared.usecase.folderstudymaterials.d dVar, boolean z) {
        super(1);
        this.a = f;
        this.b = f2;
        this.c = i;
        this.d = dVar;
        this.e = z;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        S s = (S) obj;
        float fA = s.s.a() * this.a;
        float fA2 = s.s.a() * this.b;
        s.f((fA <= DefinitionKt.NO_Float_VALUE || fA2 <= DefinitionKt.NO_Float_VALUE) ? null : new C0856p(fA, fA2, this.c));
        com.quizlet.shared.usecase.folderstudymaterials.d dVar = this.d;
        if (dVar == null) {
            dVar = F.a;
        }
        s.t(dVar);
        s.e(this.e);
        return Unit.a;
    }
}
