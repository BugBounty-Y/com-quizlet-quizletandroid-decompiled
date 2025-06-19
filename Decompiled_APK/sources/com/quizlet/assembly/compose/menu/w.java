package com.quizlet.assembly.compose.menu;

import androidx.compose.runtime.L0;
import com.quizlet.assembly.compose.modals.x;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.AbstractC4958q;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class w extends C4956o implements Function2 {
    public final /* synthetic */ Function1 a;
    public final /* synthetic */ Function0 b;
    public final /* synthetic */ s c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public w(Function1 function1, Function0 function0, s sVar) {
        super(2, AbstractC4958q.class, "onItemClick", "AssemblyPopupMenu$onItemClick(Lkotlin/jvm/functions/Function1;Lkotlin/jvm/functions/Function0;Lcom/quizlet/assembly/compose/menu/AssemblyMenuState;Lcom/quizlet/assembly/compose/menu/AssemblyMenuOptionItem$BaseOptionItem;Lcom/quizlet/assembly/compose/modals/ModalPopupState;)V", 0);
        this.a = function1;
        this.b = function0;
        this.c = sVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        o p0 = (o) obj;
        x p1 = (x) obj2;
        Intrinsics.checkNotNullParameter(p0, "p0");
        Intrinsics.checkNotNullParameter(p1, "p1");
        this.a.invoke(p0.a);
        s sVar = this.c;
        p1.a();
        this.b.invoke();
        ((L0) sVar.c).setValue(u.b);
        return Unit.a;
    }
}
