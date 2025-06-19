package androidx.work.impl.utils;

import androidx.lifecycle.X;
import androidx.lifecycle.Z;

/* loaded from: classes.dex */
public final class f implements Z {
    public Object a = null;
    public final /* synthetic */ androidx.work.impl.utils.taskexecutor.c b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ com.google.mlkit.common.internal.model.a d;
    public final /* synthetic */ X e;

    public f(androidx.work.impl.utils.taskexecutor.c cVar, Object obj, com.google.mlkit.common.internal.model.a aVar, X x) {
        this.b = cVar;
        this.c = obj;
        this.d = aVar;
        this.e = x;
    }

    @Override // androidx.lifecycle.Z
    public final void a(Object obj) {
        this.b.a(new androidx.camera.core.impl.utils.futures.h(this, false, obj, 7));
    }
}
