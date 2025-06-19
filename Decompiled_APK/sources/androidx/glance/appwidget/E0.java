package androidx.glance.appwidget;

import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class E0 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ Function2 b;
    public final /* synthetic */ long c;
    public final /* synthetic */ J0 d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public E0(J0 j0, long j, Function2 function2, int i) {
        super(2);
        this.d = j0;
        this.c = j;
        this.b = function2;
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0020  */
    @Override // kotlin.jvm.functions.Function2
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invoke(java.lang.Object r7, java.lang.Object r8) {
        /*
            r6 = this;
            int r0 = r6.a
            switch(r0) {
                case 0: goto L73;
                default: goto L5;
            }
        L5:
            androidx.compose.runtime.l r7 = (androidx.compose.runtime.InterfaceC0806l) r7
            java.lang.Number r8 = (java.lang.Number) r8
            int r8 = r8.intValue()
            r8 = r8 & 3
            r0 = 2
            if (r8 != r0) goto L20
            r8 = r7
            androidx.compose.runtime.p r8 = (androidx.compose.runtime.C0814p) r8
            boolean r0 = r8.x()
            if (r0 != 0) goto L1c
            goto L20
        L1c:
            r8.Q()
            goto L6b
        L20:
            androidx.glance.appwidget.G0 r8 = androidx.glance.appwidget.G0.a
            androidx.compose.runtime.p r7 = (androidx.compose.runtime.C0814p) r7
            r0 = 578571862(0x227c4e56, float:3.419384E-18)
            r7.Y(r0)
            r0 = -548224868(0xffffffffdf52c09c, float:-1.518631E19)
            r7.Y(r0)
            androidx.compose.runtime.a r0 = r7.a
            boolean r0 = r0 instanceof androidx.glance.b
            if (r0 == 0) goto L6e
            r7.V()
            boolean r0 = r7.O
            if (r0 == 0) goto L41
            r7.k(r8)
            goto L44
        L41:
            r7.l0()
        L44:
            androidx.compose.ui.unit.g r8 = new androidx.compose.ui.unit.g
            long r0 = r6.c
            r8.<init>(r0)
            androidx.glance.appwidget.q0 r0 = androidx.glance.appwidget.q0.x
            androidx.compose.runtime.C0776c.E(r7, r8, r0)
            androidx.glance.appwidget.q0 r8 = androidx.glance.appwidget.q0.y
            androidx.glance.appwidget.J0 r0 = r6.d
            androidx.compose.runtime.C0776c.E(r7, r0, r8)
            r8 = 0
            java.lang.Integer r0 = java.lang.Integer.valueOf(r8)
            kotlin.jvm.functions.Function2 r1 = r6.b
            r1.invoke(r7, r0)
            r0 = 1
            r7.p(r0)
            r7.p(r8)
            r7.p(r8)
        L6b:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        L6e:
            androidx.compose.runtime.C0776c.s()
            r7 = 0
            throw r7
        L73:
            r3 = r7
            androidx.compose.runtime.l r3 = (androidx.compose.runtime.InterfaceC0806l) r3
            java.lang.Number r8 = (java.lang.Number) r8
            r8.intValue()
            kotlin.jvm.functions.Function2 r5 = r6.b
            androidx.glance.appwidget.J0 r4 = r6.d
            long r1 = r6.c
            r0 = 1
            io.reactivex.rxjava3.exceptions.a.a(r0, r1, r3, r4, r5)
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.appwidget.E0.invoke(java.lang.Object, java.lang.Object):java.lang.Object");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public E0(Function2 function2, long j, J0 j0) {
        super(2);
        this.b = function2;
        this.c = j;
        this.d = j0;
    }
}
