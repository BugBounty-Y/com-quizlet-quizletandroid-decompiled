package androidx.glance.appwidget;

import android.content.Context;
import com.quizlet.quizletandroid.ui.widgets.QuizletWidgetReceiver;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class Z extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public QuizletWidgetReceiver j;
    public Context k;
    public int l;
    public int m;
    public int n;
    public /* synthetic */ Object o;
    public final /* synthetic */ QuizletWidgetReceiver p;
    public final /* synthetic */ Context q;
    public final /* synthetic */ int[] r;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Z(QuizletWidgetReceiver quizletWidgetReceiver, Context context, int[] iArr, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.p = quizletWidgetReceiver;
        this.q = context;
        this.r = iArr;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        Z z = new Z(this.p, this.q, this.r, hVar);
        z.o = obj;
        return z;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((Z) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x003b  */
    /* JADX WARN: Removed duplicated region for block: B:14:0x0057  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:11:0x0052 -> B:13:0x0055). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r9) {
        /*
            r8 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r8.n
            r2 = 1
            if (r1 == 0) goto L21
            if (r1 != r2) goto L19
            int r1 = r8.m
            int r3 = r8.l
            android.content.Context r4 = r8.k
            com.quizlet.quizletandroid.ui.widgets.QuizletWidgetReceiver r5 = r8.j
            java.lang.Object r6 = r8.o
            int[] r6 = (int[]) r6
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L55
        L19:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L21:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            java.lang.Object r9 = r8.o
            kotlinx.coroutines.C r9 = (kotlinx.coroutines.C) r9
            com.quizlet.quizletandroid.ui.widgets.QuizletWidgetReceiver r1 = r8.p
            android.content.Context r3 = r8.q
            com.quizlet.quizletandroid.ui.widgets.QuizletWidgetReceiver.a(r1, r9, r3)
            int[] r9 = r8.r
            int r4 = r9.length
            r5 = 0
            r6 = r5
            r5 = r1
            r1 = r4
            r4 = r3
            r3 = r6
            r6 = r9
        L39:
            if (r3 >= r1) goto L57
            r9 = r6[r3]
            r5.getClass()
            com.quizlet.quizletandroid.ui.widgets.y r7 = com.quizlet.quizletandroid.ui.widgets.y.c
            r8.o = r6
            r8.j = r5
            r8.k = r4
            r8.l = r3
            r8.m = r1
            r8.n = r2
            java.lang.Object r9 = r7.a(r4, r9, r8)
            if (r9 != r0) goto L55
            return r0
        L55:
            int r3 = r3 + r2
            goto L39
        L57:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.appwidget.Z.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
