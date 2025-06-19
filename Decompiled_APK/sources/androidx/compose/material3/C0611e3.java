package androidx.compose.material3;

import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.material3.e3, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0611e3 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ long a;
    public final /* synthetic */ androidx.compose.ui.graphics.drawscope.h b;
    public final /* synthetic */ androidx.compose.animation.core.J c;
    public final /* synthetic */ androidx.compose.animation.core.J d;
    public final /* synthetic */ androidx.compose.animation.core.J e;
    public final /* synthetic */ androidx.compose.animation.core.J f;
    public final /* synthetic */ float g;
    public final /* synthetic */ long h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0611e3(long j, androidx.compose.ui.graphics.drawscope.h hVar, androidx.compose.animation.core.J j2, androidx.compose.animation.core.J j3, androidx.compose.animation.core.J j4, androidx.compose.animation.core.J j5, float f, long j6) {
        super(1);
        this.a = j;
        this.b = hVar;
        this.c = j2;
        this.d = j3;
        this.e = j4;
        this.f = j5;
        this.g = f;
        this.h = j6;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        float f;
        androidx.compose.ui.graphics.drawscope.d dVar = (androidx.compose.ui.graphics.drawscope.d) obj;
        androidx.compose.ui.graphics.drawscope.h hVar = this.b;
        AbstractC0666j3.d(dVar, DefinitionKt.NO_Float_VALUE, 360.0f, this.a, hVar);
        float fFloatValue = (((Number) this.c.getValue()).floatValue() * 216.0f) % 360.0f;
        float fFloatValue2 = ((Number) this.d.getValue()).floatValue();
        androidx.compose.animation.core.J j = this.e;
        float fAbs = Math.abs(fFloatValue2 - ((Number) j.getValue()).floatValue());
        float fFloatValue3 = ((Number) j.getValue()).floatValue() + ((Number) this.f.getValue()).floatValue() + (fFloatValue - 90.0f);
        if (hVar.c == 0) {
            f = DefinitionKt.NO_Float_VALUE;
        } else {
            f = ((this.g / (AbstractC0666j3.e / 2)) * 57.29578f) / 2.0f;
        }
        AbstractC0666j3.d(dVar, fFloatValue3 + f, Math.max(fAbs, 0.1f), this.h, hVar);
        return Unit.a;
    }
}
