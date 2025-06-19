package com.quizlet.assembly.compose.menu;

import androidx.compose.runtime.L0;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.AbstractC4958q;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class d extends C4956o implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ Function0 c;
    public final /* synthetic */ s d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(Function1 function1, Function0 function0, s sVar, int i) {
        super(1, AbstractC4958q.class, "onItemClick", "AssemblyDropdownMenu_IBZr_mw$onItemClick(Lkotlin/jvm/functions/Function1;Lkotlin/jvm/functions/Function0;Lcom/quizlet/assembly/compose/menu/AssemblyMenuState;Lcom/quizlet/assembly/compose/menu/AssemblyMenuOptionItem$BaseOptionItem;)V", 0);
        this.a = i;
        switch (i) {
            case 1:
                this.b = function1;
                this.c = function0;
                this.d = sVar;
                super(1, AbstractC4958q.class, "onItemClick", "AssemblyLazyDropdownMenu_IBZr_mw$onItemClick$11(Lkotlin/jvm/functions/Function1;Lkotlin/jvm/functions/Function0;Lcom/quizlet/assembly/compose/menu/AssemblyMenuState;Lcom/quizlet/assembly/compose/menu/AssemblyMenuOptionItem$BaseOptionItem;)V", 0);
                break;
            default:
                this.b = function1;
                this.c = function0;
                this.d = sVar;
                break;
        }
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                o p0 = (o) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                this.b.invoke(p0.a);
                this.c.invoke();
                s sVar = this.d;
                sVar.getClass();
                ((L0) sVar.c).setValue(u.b);
                break;
            default:
                o p02 = (o) obj;
                Intrinsics.checkNotNullParameter(p02, "p0");
                this.b.invoke(p02.a);
                s sVar2 = this.d;
                this.c.invoke();
                ((L0) sVar2.c).setValue(u.b);
                break;
        }
        return Unit.a;
    }
}
