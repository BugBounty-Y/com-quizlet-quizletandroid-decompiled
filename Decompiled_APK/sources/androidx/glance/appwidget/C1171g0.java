package androidx.glance.appwidget;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.glance.appwidget.g0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1171g0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C1173h0 l;
    public final /* synthetic */ C1162c m;
    public final /* synthetic */ com.quizlet.quizletandroid.ui.widgets.y n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1171g0(C1173h0 c1173h0, C1162c c1162c, com.quizlet.quizletandroid.ui.widgets.y yVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c1173h0;
        this.m = c1162c;
        this.n = yVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1171g0 c1171g0 = new C1171g0(this.l, this.m, this.n, hVar);
        c1171g0.k = obj;
        return c1171g0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1171g0) create((androidx.glance.session.o) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:26:0x0088 A[RETURN] */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r11) {
        /*
            r10 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r10.j
            androidx.glance.appwidget.h0 r2 = r10.l
            androidx.glance.appwidget.c r3 = r10.m
            r4 = 0
            androidx.glance.appwidget.GlanceRemoteViewsService r2 = r2.a
            r5 = 3
            r6 = 2
            r7 = 1
            if (r1 == 0) goto L32
            if (r1 == r7) goto L2a
            if (r1 == r6) goto L22
            if (r1 != r5) goto L1a
            androidx.glance.appwidget.protobuf.Z.e(r11)
            return r11
        L1a:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r0)
            throw r11
        L22:
            java.lang.Object r1 = r10.k
            androidx.glance.session.o r1 = (androidx.glance.session.o) r1
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L6a
        L2a:
            java.lang.Object r1 = r10.k
            androidx.glance.session.o r1 = (androidx.glance.session.o) r1
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L4d
        L32:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            java.lang.Object r11 = r10.k
            androidx.glance.session.o r11 = (androidx.glance.session.o) r11
            int r1 = r3.a
            java.lang.String r1 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3225o7.e(r1)
            r10.k = r11
            r10.j = r7
            java.lang.Object r1 = r11.a(r2, r1, r10)
            if (r1 != r0) goto L4a
            goto L87
        L4a:
            r9 = r1
            r1 = r11
            r11 = r9
        L4d:
            java.lang.Boolean r11 = (java.lang.Boolean) r11
            boolean r11 = r11.booleanValue()
            if (r11 == 0) goto L56
            return r4
        L56:
            androidx.glance.appwidget.m r11 = new androidx.glance.appwidget.m
            com.quizlet.quizletandroid.ui.widgets.y r7 = r10.n
            r8 = 252(0xfc, float:3.53E-43)
            r11.<init>(r7, r3, r4, r8)
            r10.k = r1
            r10.j = r6
            java.lang.Object r11 = r1.b(r2, r11, r10)
            if (r11 != r0) goto L6a
            goto L87
        L6a:
            int r11 = r3.a
            java.lang.String r11 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3225o7.e(r11)
            java.util.LinkedHashMap r1 = r1.a
            java.lang.Object r11 = r1.get(r11)
            androidx.glance.appwidget.m r11 = (androidx.glance.appwidget.C1182m) r11
            java.lang.String r1 = "null cannot be cast to non-null type androidx.glance.appwidget.AppWidgetSession"
            kotlin.jvm.internal.Intrinsics.e(r11, r1)
            r10.k = r4
            r10.j = r5
            java.lang.Object r11 = r11.f(r10)
            if (r11 != r0) goto L88
        L87:
            return r0
        L88:
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.appwidget.C1171g0.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
