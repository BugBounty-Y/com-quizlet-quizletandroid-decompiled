package androidx.compose.material3;

import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.material3.g3, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0623g3 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ long a;
    public final /* synthetic */ int b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0623g3(int i, long j) {
        super(1);
        this.a = j;
        this.b = i;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        androidx.compose.ui.graphics.drawscope.d dVar = (androidx.compose.ui.graphics.drawscope.d) obj;
        float fMin = Math.min(dVar.c0(AbstractC0605d3.d), androidx.compose.ui.geometry.e.b(dVar.g()));
        float fB = (androidx.compose.ui.geometry.e.b(dVar.g()) - fMin) / 2;
        long j = this.a;
        if (this.b == 1) {
            float f = fMin / 2.0f;
            androidx.compose.ui.graphics.drawscope.d.V(dVar, j, f, com.google.android.gms.internal.mlkit_vision_barcode.Q4.c((androidx.compose.ui.geometry.e.d(dVar.g()) - f) - fB, androidx.compose.ui.geometry.e.b(dVar.g()) / 2.0f), null, 120);
        } else {
            androidx.compose.ui.graphics.drawscope.d.I(dVar, j, com.google.android.gms.internal.mlkit_vision_barcode.Q4.c((androidx.compose.ui.geometry.e.d(dVar.g()) - fMin) - fB, (androidx.compose.ui.geometry.e.b(dVar.g()) - fMin) / 2.0f), com.google.android.gms.internal.mlkit_vision_barcode.T4.a(fMin, fMin), DefinitionKt.NO_Float_VALUE, 120);
        }
        return Unit.a;
    }
}
