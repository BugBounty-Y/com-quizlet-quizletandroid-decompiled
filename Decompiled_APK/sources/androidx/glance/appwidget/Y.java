package androidx.glance.appwidget;

import android.content.Context;
import android.os.Bundle;
import androidx.compose.material.C0574q;
import com.quizlet.quizletandroid.ui.widgets.QuizletWidgetReceiver;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class Y extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ QuizletWidgetReceiver l;
    public final /* synthetic */ Context m;
    public final /* synthetic */ int n;
    public final /* synthetic */ Bundle o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Y(QuizletWidgetReceiver quizletWidgetReceiver, Context context, int i, Bundle bundle, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = quizletWidgetReceiver;
        this.m = context;
        this.n = i;
        this.o = bundle;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        Y y = new Y(this.l, this.m, this.n, this.o, hVar);
        y.k = obj;
        return y;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((Y) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            QuizletWidgetReceiver.a(this.l, (kotlinx.coroutines.C) this.k, this.m);
            com.quizlet.quizletandroid.ui.widgets.y yVar = com.quizlet.quizletandroid.ui.widgets.y.c;
            this.j = 1;
            yVar.getClass();
            H0 h0 = com.quizlet.quizletandroid.ui.widgets.y.d;
            C1162c c1162c = new C1162c(this.n);
            Bundle bundle = this.o;
            Object objA = yVar.a.a(new L(this.m, c1162c, yVar, bundle, new C0574q(bundle, (kotlin.coroutines.h) null, 2), null), this);
            if (objA != aVar) {
                objA = Unit.a;
            }
            if (objA != aVar) {
                objA = Unit.a;
            }
            if (objA == aVar) {
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
