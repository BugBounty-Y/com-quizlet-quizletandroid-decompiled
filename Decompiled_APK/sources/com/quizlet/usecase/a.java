package com.quizlet.usecase;

import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.W;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.internal.AbstractC4993a;

/* loaded from: classes3.dex */
public final class a implements b {
    public final AbstractC4993a a;

    /* JADX WARN: Multi-variable type inference failed */
    public a(W flow) {
        Intrinsics.checkNotNullParameter(flow, "flow");
        this.a = (AbstractC4993a) flow;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [kotlinx.coroutines.flow.W, kotlinx.coroutines.flow.internal.a] */
    public final void a(Object obj) {
        this.a.h(obj);
    }

    public /* synthetic */ a(int i) {
        this((i & 1) != 0 ? 0 : 3, kotlinx.coroutines.channels.a.a);
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public a(int i, kotlinx.coroutines.channels.a onBufferOverflow) {
        this(e0.a(i, 1, onBufferOverflow));
        Intrinsics.checkNotNullParameter(onBufferOverflow, "onBufferOverflow");
    }
}
