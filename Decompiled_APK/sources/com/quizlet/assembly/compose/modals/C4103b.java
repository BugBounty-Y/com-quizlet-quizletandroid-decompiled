package com.quizlet.assembly.compose.modals;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* renamed from: com.quizlet.assembly.compose.modals.b, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C4103b implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ x b;
    public final /* synthetic */ Function0 c;

    public /* synthetic */ C4103b(x xVar, Function0 function0, int i) {
        this.a = i;
        this.b = xVar;
        this.c = function0;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.a();
                this.c.invoke();
                break;
            case 1:
                this.b.a();
                this.c.invoke();
                break;
            case 2:
                this.c.invoke();
                this.b.a();
                break;
            case 3:
                this.c.invoke();
                this.b.a();
                break;
            case 4:
                this.b.a();
                this.c.invoke();
                break;
            case 5:
                this.c.invoke();
                this.b.a();
                break;
            case 6:
                this.b.a();
                this.c.invoke();
                break;
            case 7:
                this.b.a();
                this.c.invoke();
                break;
            case 8:
                this.b.a();
                this.c.invoke();
                break;
            default:
                this.b.a();
                this.c.invoke();
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ C4103b(Function0 function0, x xVar, int i) {
        this.a = i;
        this.c = function0;
        this.b = xVar;
    }
}
