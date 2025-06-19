package com.quizlet.quizletandroid.ui.common.ads;

import androidx.compose.foundation.K;
import androidx.paging.J0;
import kotlin.Unit;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.InterfaceC5002j;
import kotlinx.coroutines.flow.W;

/* loaded from: classes3.dex */
public final class z implements InterfaceC4992i {
    public final /* synthetic */ J0 a;
    public final /* synthetic */ C4634a b;
    public final /* synthetic */ C4639f c;
    public final /* synthetic */ W d;

    public z(J0 j0, C4634a c4634a, C4639f c4639f, W w) {
        this.a = j0;
        this.b = c4634a;
        this.c = c4639f;
        this.d = w;
    }

    @Override // kotlinx.coroutines.flow.InterfaceC4992i
    public final Object b(InterfaceC5002j interfaceC5002j, kotlin.coroutines.h hVar) {
        Object objB = this.a.b(new K(interfaceC5002j, this.b, this.c, this.d, 3), hVar);
        return objB == kotlin.coroutines.intrinsics.a.a ? objB : Unit.a;
    }
}
