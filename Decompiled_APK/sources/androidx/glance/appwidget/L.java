package androidx.glance.appwidget;

import android.content.Context;
import android.os.Bundle;
import com.quizlet.quizletandroid.ui.widgets.AbstractC4769b;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class L extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ Context l;
    public final /* synthetic */ C1162c m;
    public final /* synthetic */ AbstractC4769b n;
    public final /* synthetic */ Bundle o;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public L(Context context, C1162c c1162c, AbstractC4769b abstractC4769b, Bundle bundle, kotlin.jvm.functions.c cVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = context;
        this.m = c1162c;
        this.n = abstractC4769b;
        this.o = bundle;
        this.p = (kotlin.coroutines.jvm.internal.i) cVar;
    }

    /* JADX WARN: Type inference failed for: r5v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.c] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        ?? r5 = this.p;
        L l = new L(this.l, this.m, this.n, this.o, r5, hVar);
        l.k = obj;
        return l;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((L) create((androidx.glance.session.o) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:22:0x0085, code lost:
    
        if (r11.p.invoke(r1, r12, r11) != r0) goto L24;
     */
    /* JADX WARN: Type inference failed for: r2v4, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.c] */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r12) {
        /*
            r11 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r11.j
            androidx.glance.appwidget.c r2 = r11.m
            int r3 = r2.a
            android.content.Context r4 = r11.l
            r5 = 3
            r6 = 2
            r7 = 1
            if (r1 == 0) goto L32
            if (r1 == r7) goto L2a
            if (r1 == r6) goto L22
            if (r1 != r5) goto L1a
            androidx.glance.appwidget.protobuf.Z.e(r12)
            goto L88
        L1a:
            java.lang.IllegalStateException r12 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r12.<init>(r0)
            throw r12
        L22:
            java.lang.Object r1 = r11.k
            androidx.glance.session.o r1 = (androidx.glance.session.o) r1
            androidx.glance.appwidget.protobuf.Z.e(r12)
            goto L69
        L2a:
            java.lang.Object r1 = r11.k
            androidx.glance.session.o r1 = (androidx.glance.session.o) r1
            androidx.glance.appwidget.protobuf.Z.e(r12)
            goto L4b
        L32:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            java.lang.Object r12 = r11.k
            androidx.glance.session.o r12 = (androidx.glance.session.o) r12
            java.lang.String r1 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3225o7.e(r3)
            r11.k = r12
            r11.j = r7
            java.lang.Object r1 = r12.a(r4, r1, r11)
            if (r1 != r0) goto L48
            goto L87
        L48:
            r10 = r1
            r1 = r12
            r12 = r10
        L4b:
            java.lang.Boolean r12 = (java.lang.Boolean) r12
            boolean r12 = r12.booleanValue()
            if (r12 != 0) goto L69
            androidx.glance.appwidget.m r12 = new androidx.glance.appwidget.m
            android.os.Bundle r7 = r11.o
            com.quizlet.quizletandroid.ui.widgets.b r8 = r11.n
            r9 = 248(0xf8, float:3.48E-43)
            r12.<init>(r8, r2, r7, r9)
            r11.k = r1
            r11.j = r6
            java.lang.Object r12 = r1.b(r4, r12, r11)
            if (r12 != r0) goto L69
            goto L87
        L69:
            java.lang.String r12 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3225o7.e(r3)
            java.util.LinkedHashMap r2 = r1.a
            java.lang.Object r12 = r2.get(r12)
            androidx.glance.appwidget.m r12 = (androidx.glance.appwidget.C1182m) r12
            java.lang.String r2 = "null cannot be cast to non-null type androidx.glance.appwidget.AppWidgetSession"
            kotlin.jvm.internal.Intrinsics.e(r12, r2)
            r2 = 0
            r11.k = r2
            r11.j = r5
            kotlin.coroutines.jvm.internal.i r2 = r11.p
            java.lang.Object r12 = r2.invoke(r1, r12, r11)
            if (r12 != r0) goto L88
        L87:
            return r0
        L88:
            kotlin.Unit r12 = kotlin.Unit.a
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.appwidget.L.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
