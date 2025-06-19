package kotlinx.serialization.json.internal;

import androidx.appcompat.widget.C0070a;
import java.util.LinkedHashMap;
import kotlin.AbstractC4908b;

/* loaded from: classes3.dex */
public final class t extends kotlin.coroutines.jvm.internal.c {
    public AbstractC4908b j;
    public C0070a k;
    public LinkedHashMap l;
    public String m;
    public /* synthetic */ Object n;
    public final /* synthetic */ C0070a o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public t(C0070a c0070a, kotlin.coroutines.jvm.internal.a aVar) {
        super(aVar);
        this.o = c0070a;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return C0070a.d(this.o, null, this);
    }
}
