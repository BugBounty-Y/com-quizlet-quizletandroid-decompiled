package androidx.glance.appwidget;

import android.content.Context;
import android.util.Log;
import com.quizlet.quizletandroid.ui.widgets.QuizletWidgetReceiver;
import java.util.concurrent.CancellationException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.glance.appwidget.d0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1165d0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ Context k;
    public final /* synthetic */ QuizletWidgetReceiver l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1165d0(Context context, QuizletWidgetReceiver quizletWidgetReceiver, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = context;
        this.l = quizletWidgetReceiver;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C1165d0(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1165d0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        try {
            if (i == 0) {
                androidx.glance.appwidget.protobuf.Z.e(obj);
                Context context = this.k;
                QuizletWidgetReceiver quizletWidgetReceiver = this.l;
                X x = new X(context);
                com.quizlet.quizletandroid.ui.widgets.y yVar = com.quizlet.quizletandroid.ui.widgets.y.c;
                this.j = 1;
                if (x.c(quizletWidgetReceiver, yVar, this) == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                androidx.glance.appwidget.protobuf.Z.e(obj);
            }
        } catch (CancellationException unused) {
        } catch (Throwable th) {
            Log.e("GlanceAppWidget", "Error in Glance App Widget", th);
        }
        return Unit.a;
    }
}
