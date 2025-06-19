package com.quizlet.quizletandroid.interactor;

import kotlin.Unit;
import kotlinx.coroutines.flow.C4986c;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes3.dex */
public final class f implements InterfaceC4992i {
    public final /* synthetic */ int a;
    public final /* synthetic */ C4986c b;
    public final /* synthetic */ m c;

    public /* synthetic */ f(C4986c c4986c, m mVar, int i) {
        this.a = i;
        this.b = c4986c;
        this.c = mVar;
    }

    @Override // kotlinx.coroutines.flow.InterfaceC4992i
    public final Object b(InterfaceC5002j interfaceC5002j, kotlin.coroutines.h hVar) {
        switch (this.a) {
            case 0:
                Object objB = this.b.b(new e(interfaceC5002j, this.c, 0), hVar);
                if (objB != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
            default:
                Object objB2 = this.b.b(new e(interfaceC5002j, this.c, 1), hVar);
                if (objB2 != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
        }
        return Unit.a;
    }
}
