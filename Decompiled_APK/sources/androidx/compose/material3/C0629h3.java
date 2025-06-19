package androidx.compose.material3;

import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.material3.h3, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0629h3 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ float b;
    public final /* synthetic */ Function0 c;
    public final /* synthetic */ long d;
    public final /* synthetic */ long e;
    public final /* synthetic */ Function1 f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0629h3(int i, float f, Function0 function0, long j, long j2, Function1 function1) {
        super(1);
        this.a = i;
        this.b = f;
        this.c = function0;
        this.d = j;
        this.e = j2;
        this.f = function1;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        androidx.compose.ui.graphics.drawscope.d dVar = (androidx.compose.ui.graphics.drawscope.d) obj;
        float fB = androidx.compose.ui.geometry.e.b(dVar.g());
        int i = this.a;
        float fR = this.b;
        if (i != 0 && androidx.compose.ui.geometry.e.b(dVar.g()) <= androidx.compose.ui.geometry.e.d(dVar.g())) {
            fR += dVar.R(fB);
        }
        float fR2 = fR / dVar.R(androidx.compose.ui.geometry.e.d(dVar.g()));
        float fFloatValue = ((Number) this.c.invoke()).floatValue();
        float fMin = Math.min(fFloatValue, fR2) + fFloatValue;
        if (fMin <= 1.0f) {
            AbstractC0666j3.c(dVar, fMin, 1.0f, this.d, fB, this.a);
        }
        AbstractC0666j3.c(dVar, DefinitionKt.NO_Float_VALUE, fFloatValue, this.e, fB, this.a);
        this.f.invoke(dVar);
        return Unit.a;
    }
}
