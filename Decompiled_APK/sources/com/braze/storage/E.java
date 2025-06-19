package com.braze.storage;

import androidx.compose.runtime.C0776c;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class E implements Function0 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ boolean c;

    public /* synthetic */ E(boolean z, boolean z2) {
        this.b = z;
        this.c = z2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return r.a(this.b, this.c);
            default:
                return new com.quizlet.assembly.compose.modals.x(this.b ? C0776c.z(com.quizlet.assembly.compose.modals.y.a) : C0776c.z(com.quizlet.assembly.compose.modals.y.b), this.c);
        }
    }

    public /* synthetic */ E(boolean z, boolean z2, boolean z3) {
        this.b = z;
        this.c = z2;
    }
}
