package org.koin.core.instance;

import com.quizlet.data.repository.set.f;
import com.quizlet.upgrade.ui.fragment.m;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends b {
    public Object b;

    @Override // org.koin.core.instance.b
    public final Object a(f context) {
        Intrinsics.checkNotNullParameter(context, "context");
        Object obj = this.b;
        if (obj == null) {
            return super.a(context);
        }
        if (obj != null) {
            return obj;
        }
        throw new IllegalStateException("Single instance created couldn't return value");
    }

    @Override // org.koin.core.instance.b
    public final Object b(f context) {
        Intrinsics.checkNotNullParameter(context, "context");
        m block = new m(2, this, context);
        Intrinsics.checkNotNullParameter(this, "lock");
        Intrinsics.checkNotNullParameter(block, "block");
        synchronized (this) {
            block.invoke();
        }
        Object obj = this.b;
        if (obj != null) {
            return obj;
        }
        throw new IllegalStateException("Single instance created couldn't return value");
    }
}
