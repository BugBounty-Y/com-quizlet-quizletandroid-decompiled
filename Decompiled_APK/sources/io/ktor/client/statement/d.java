package io.ktor.client.statement;

import androidx.datastore.preferences.protobuf.h0;
import java.nio.charset.CharsetDecoder;

/* loaded from: classes3.dex */
public final class d extends kotlin.coroutines.jvm.internal.c {
    public CharsetDecoder j;
    public /* synthetic */ Object k;
    public int l;

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.l |= Integer.MIN_VALUE;
        return h0.a(null, null, this);
    }
}
