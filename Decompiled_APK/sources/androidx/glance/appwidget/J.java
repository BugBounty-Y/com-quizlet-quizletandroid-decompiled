package androidx.glance.appwidget;

import android.content.Context;
import com.quizlet.quizletandroid.ui.widgets.AbstractC4769b;

/* loaded from: classes.dex */
public final class J extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public Context k;
    public int l;
    public /* synthetic */ Object m;
    public final /* synthetic */ AbstractC4769b n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public J(AbstractC4769b abstractC4769b, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = abstractC4769b;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.a(null, 0, this);
    }
}
