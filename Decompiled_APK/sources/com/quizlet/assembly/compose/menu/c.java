package com.quizlet.assembly.compose.menu;

import androidx.compose.runtime.L0;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.AbstractC4958q;
import kotlin.jvm.internal.C4956o;

/* loaded from: classes2.dex */
public final /* synthetic */ class c extends C4956o implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function0 b;
    public final /* synthetic */ s c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(Function0 function0, s sVar, int i) {
        super(0, AbstractC4958q.class, "hideMenu", "AssemblyDropdownMenu_IBZr_mw$hideMenu(Lkotlin/jvm/functions/Function0;Lcom/quizlet/assembly/compose/menu/AssemblyMenuState;)V", 0);
        this.a = i;
        switch (i) {
            case 1:
                this.b = function0;
                this.c = sVar;
                super(0, AbstractC4958q.class, "hideMenu", "AssemblyLazyDropdownMenu_IBZr_mw$hideMenu$10(Lkotlin/jvm/functions/Function0;Lcom/quizlet/assembly/compose/menu/AssemblyMenuState;)V", 0);
                break;
            default:
                this.b = function0;
                this.c = sVar;
                break;
        }
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.invoke();
                s sVar = this.c;
                sVar.getClass();
                ((L0) sVar.c).setValue(u.b);
                break;
            default:
                s sVar2 = this.c;
                this.b.invoke();
                ((L0) sVar2.c).setValue(u.b);
                break;
        }
        return Unit.a;
    }
}
