package com.quizlet.ui.compose.animations;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.H;
import kotlinx.collections.immutable.e;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ H k;
    public final /* synthetic */ e l;
    public final /* synthetic */ InterfaceC0773a0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(H h, e eVar, InterfaceC0773a0 interfaceC0773a0, h hVar) {
        super(2, hVar);
        this.k = h;
        this.l = eVar;
        this.m = interfaceC0773a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
        return kotlin.coroutines.intrinsics.a.a;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            if (E.n(1000 * 2, this) != aVar) {
            }
            return aVar;
        }
        if (i != 1 && i != 2) {
            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
        }
        Z.e(obj);
        do {
            H h = this.k;
            int i2 = h.a;
            e eVar = this.l;
            if (i2 >= eVar.size() - 1) {
                h.a = 0;
            } else {
                int i3 = h.a;
                h.a = i3 + 1;
                new Integer(i3);
            }
            this.m.setValue((String) eVar.get(h.a));
            this.j = 2;
        } while (E.n(1000 * 4, this) != aVar);
        return aVar;
    }
}
