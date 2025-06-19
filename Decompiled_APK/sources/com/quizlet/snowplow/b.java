package com.quizlet.snowplow;

import com.snowplowanalytics.snowplow.configuration.i;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.c {
    public a j;
    public com.snowplowanalytics.snowplow.configuration.e k;
    public com.snowplowanalytics.snowplow.configuration.d l;
    public i m;
    public /* synthetic */ Object n;
    public final /* synthetic */ SnowplowInitializer o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(SnowplowInitializer snowplowInitializer, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.o = snowplowInitializer;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return SnowplowInitializer.a(this.o, null, this);
    }
}
