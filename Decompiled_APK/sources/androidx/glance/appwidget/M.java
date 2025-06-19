package androidx.glance.appwidget;

import android.content.Context;
import com.quizlet.quizletandroid.ui.widgets.AbstractC4769b;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class M extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ Context l;
    public final /* synthetic */ C1162c m;
    public final /* synthetic */ AbstractC4769b n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public M(Context context, C1162c c1162c, AbstractC4769b abstractC4769b, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = context;
        this.m = c1162c;
        this.n = abstractC4769b;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        M m = new M(this.l, this.m, this.n, hVar);
        m.k = obj;
        return m;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((M) create((androidx.glance.session.o) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:18:0x005f, code lost:
    
        if (r1.b(r4, r9, r8) == r0) goto L27;
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x0085, code lost:
    
        if (r9 == r0) goto L27;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r9) {
        /*
            r8 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r8.j
            androidx.glance.appwidget.c r2 = r8.m
            int r3 = r2.a
            android.content.Context r4 = r8.l
            r5 = 3
            r6 = 2
            r7 = 1
            if (r1 == 0) goto L2e
            if (r1 == r7) goto L26
            if (r1 == r6) goto L22
            if (r1 != r5) goto L1a
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L88
        L1a:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L22:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L62
        L26:
            java.lang.Object r1 = r8.k
            androidx.glance.session.o r1 = (androidx.glance.session.o) r1
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L45
        L2e:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            java.lang.Object r9 = r8.k
            r1 = r9
            androidx.glance.session.o r1 = (androidx.glance.session.o) r1
            java.lang.String r9 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3225o7.e(r3)
            r8.k = r1
            r8.j = r7
            java.lang.Object r9 = r1.a(r4, r9, r8)
            if (r9 != r0) goto L45
            goto L87
        L45:
            java.lang.Boolean r9 = (java.lang.Boolean) r9
            boolean r9 = r9.booleanValue()
            r7 = 0
            if (r9 != 0) goto L65
            androidx.glance.appwidget.m r9 = new androidx.glance.appwidget.m
            com.quizlet.quizletandroid.ui.widgets.b r3 = r8.n
            r5 = 248(0xf8, float:3.48E-43)
            r9.<init>(r3, r2, r7, r5)
            r8.k = r7
            r8.j = r6
            java.lang.Object r9 = r1.b(r4, r9, r8)
            if (r9 != r0) goto L62
            goto L87
        L62:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        L65:
            java.lang.String r9 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3225o7.e(r3)
            java.util.LinkedHashMap r1 = r1.a
            java.lang.Object r9 = r1.get(r9)
            androidx.glance.appwidget.m r9 = (androidx.glance.appwidget.C1182m) r9
            java.lang.String r1 = "null cannot be cast to non-null type androidx.glance.appwidget.AppWidgetSession"
            kotlin.jvm.internal.Intrinsics.e(r9, r1)
            r8.k = r7
            r8.j = r5
            androidx.glance.appwidget.f r1 = androidx.glance.appwidget.C1168f.a
            java.lang.Object r9 = r9.e(r1, r8)
            if (r9 != r0) goto L83
            goto L85
        L83:
            kotlin.Unit r9 = kotlin.Unit.a
        L85:
            if (r9 != r0) goto L88
        L87:
            return r0
        L88:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.appwidget.M.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
