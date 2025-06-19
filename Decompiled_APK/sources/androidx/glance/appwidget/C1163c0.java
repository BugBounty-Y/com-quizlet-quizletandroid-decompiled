package androidx.glance.appwidget;

import android.content.Context;
import com.quizlet.quizletandroid.ui.widgets.QuizletWidgetReceiver;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C4980e;

/* renamed from: androidx.glance.appwidget.c0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1163c0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ QuizletWidgetReceiver l;
    public final /* synthetic */ Context m;
    public final /* synthetic */ int[] n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1163c0(QuizletWidgetReceiver quizletWidgetReceiver, Context context, int[] iArr, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = quizletWidgetReceiver;
        this.m = context;
        this.n = iArr;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1163c0 c1163c0 = new C1163c0(this.l, this.m, this.n, hVar);
        c1163c0.k = obj;
        return c1163c0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1163c0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.k;
            QuizletWidgetReceiver quizletWidgetReceiver = this.l;
            Context context = this.m;
            QuizletWidgetReceiver.a(quizletWidgetReceiver, c, context);
            int[] iArr = this.n;
            ArrayList arrayList = new ArrayList(iArr.length);
            for (int i2 : iArr) {
                arrayList.add(kotlinx.coroutines.E.f(c, null, new C1161b0(quizletWidgetReceiver, context, i2, null), 3));
            }
            this.j = 1;
            if ((arrayList.isEmpty() ? kotlin.collections.K.a : new C4980e((kotlinx.coroutines.H[]) arrayList.toArray(new kotlinx.coroutines.H[0])).a(this)) == aVar) {
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
