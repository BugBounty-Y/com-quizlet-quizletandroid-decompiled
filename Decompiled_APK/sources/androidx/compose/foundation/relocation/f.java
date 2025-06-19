package androidx.compose.foundation.relocation;

import androidx.compose.ui.node.a0;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.AbstractC4958q;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final /* synthetic */ class f extends C4956o implements Function0 {
    public final /* synthetic */ j a;
    public final /* synthetic */ a0 b;
    public final /* synthetic */ r c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public f(j jVar, a0 a0Var, Function0 function0) {
        super(0, AbstractC4958q.class, "localRect", "bringChildIntoView$localRect(Landroidx/compose/foundation/relocation/BringIntoViewResponderNode;Landroidx/compose/ui/layout/LayoutCoordinates;Lkotlin/jvm/functions/Function0;)Landroidx/compose/ui/geometry/Rect;", 0);
        this.a = jVar;
        this.b = a0Var;
        this.c = (r) function0;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        ?? r0 = this.c;
        return j.M0(this.a, this.b, r0);
    }
}
