package com.quizlet.shared.quizletapi.base;

import com.google.android.gms.internal.mlkit_vision_barcode.R4;
import java.io.Serializable;
import kotlin.r;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.c {
    public c j;
    public R4 k;
    public /* synthetic */ Object l;
    public final /* synthetic */ c m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(c cVar, kotlin.coroutines.jvm.internal.c cVar2) {
        super(cVar2);
        this.m = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        Serializable serializableD = c.d(this.m, null, this);
        return serializableD == kotlin.coroutines.intrinsics.a.a ? serializableD : new r(serializableD);
    }
}
