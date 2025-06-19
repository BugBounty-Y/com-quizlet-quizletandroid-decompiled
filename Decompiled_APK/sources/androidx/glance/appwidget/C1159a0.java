package androidx.glance.appwidget;

import android.content.Context;
import androidx.compose.material.C0574q;
import com.quizlet.quizletandroid.ui.widgets.QuizletWidgetReceiver;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.glance.appwidget.a0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1159a0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ QuizletWidgetReceiver l;
    public final /* synthetic */ Context m;
    public final /* synthetic */ int n;
    public final /* synthetic */ String o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1159a0(QuizletWidgetReceiver quizletWidgetReceiver, Context context, int i, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = quizletWidgetReceiver;
        this.m = context;
        this.n = i;
        this.o = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1159a0 c1159a0 = new C1159a0(this.l, this.m, this.n, this.o, hVar);
        c1159a0.k = obj;
        return c1159a0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1159a0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
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
            Object objA = yVar.a.a(new L(this.m, new C1162c(this.n), yVar, null, new C0574q(this.o, (kotlin.coroutines.h) null, 3), null), this);
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
