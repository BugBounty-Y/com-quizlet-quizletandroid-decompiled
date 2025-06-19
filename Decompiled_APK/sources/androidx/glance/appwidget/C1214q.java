package androidx.glance.appwidget;

import android.content.Context;
import com.quizlet.quizletandroid.ui.widgets.AbstractC4769b;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.glance.appwidget.q, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1214q extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ AbstractC4769b l;
    public final /* synthetic */ Context m;
    public final /* synthetic */ C1162c n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1214q(Context context, C1162c c1162c, AbstractC4769b abstractC4769b, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = abstractC4769b;
        this.m = context;
        this.n = c1162c;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1214q c1214q = new C1214q(this.m, this.n, this.l, hVar);
        c1214q.k = obj;
        return c1214q;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1214q) create((kotlinx.coroutines.channels.u) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            C1188p c1188p = new C1188p(new AtomicReference(null), (kotlinx.coroutines.channels.u) this.k);
            C1184n c1184n = new C1184n(this.m, this.n, this.l, null);
            this.j = 1;
            if (kotlinx.coroutines.E.J(c1188p, c1184n, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        return Unit.a;
    }
}
