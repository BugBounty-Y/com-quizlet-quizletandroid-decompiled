package androidx.glance.appwidget;

import android.content.Context;
import com.quizlet.quizletandroid.ui.widgets.AbstractC4769b;
import com.quizlet.quizletandroid.ui.widgets.QuizletWidgetReceiver;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.glance.appwidget.b0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1161b0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ QuizletWidgetReceiver k;
    public final /* synthetic */ Context l;
    public final /* synthetic */ int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1161b0(QuizletWidgetReceiver quizletWidgetReceiver, Context context, int i, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = quizletWidgetReceiver;
        this.l = context;
        this.m = i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C1161b0(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1161b0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            com.quizlet.quizletandroid.ui.widgets.y yVar = com.quizlet.quizletandroid.ui.widgets.y.c;
            this.j = 1;
            if (AbstractC4769b.c(yVar, this.l, this.m, this) == aVar) {
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
