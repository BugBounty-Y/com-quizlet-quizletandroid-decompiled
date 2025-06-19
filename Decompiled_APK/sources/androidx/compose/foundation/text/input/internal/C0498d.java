package androidx.compose.foundation.text.input.internal;

import androidx.compose.runtime.L0;
import androidx.compose.ui.graphics.J;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.AbstractC4958q;
import kotlin.jvm.internal.C4956o;

/* renamed from: androidx.compose.foundation.text.input.internal.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C0498d extends C4956o implements Function1 {
    public final /* synthetic */ w a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0498d(w wVar) {
        super(1, AbstractC4958q.class, "localToScreen", "startInput$localToScreen(Landroidx/compose/foundation/text/input/internal/LegacyPlatformTextInputServiceAdapter$LegacyPlatformTextInputNode;[F)V", 0);
        this.a = wVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        float[] fArr = ((J) obj).a;
        androidx.compose.ui.layout.r rVar = (androidx.compose.ui.layout.r) ((L0) this.a.q).getValue();
        if (rVar != null) {
            if (!rVar.k()) {
                rVar = null;
            }
            if (rVar != null) {
                rVar.m(fArr);
            }
        }
        return Unit.a;
    }
}
