package androidx.paging;

import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* renamed from: androidx.paging.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1319i extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public final /* synthetic */ int j;
    public int k;
    public Object l;
    public /* synthetic */ Object m;
    public /* synthetic */ Object n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C1319i(Object obj, kotlin.coroutines.h hVar, int i) {
        super(3, hVar);
        this.j = i;
        this.n = obj;
    }

    /* JADX WARN: Type inference failed for: r1v12, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    /* JADX WARN: Type inference failed for: r1v30, types: [java.lang.Object, kotlin.jvm.functions.c] */
    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        switch (this.j) {
            case 0:
                C1319i c1319i = new C1319i((kotlin.coroutines.h) obj3, (androidx.lifecycle.viewmodel.internal.a) this.n, 0);
                c1319i.l = (InterfaceC5002j) obj;
                c1319i.m = obj2;
                return c1319i.invokeSuspend(Unit.a);
            case 1:
                ((Boolean) obj2).booleanValue();
                C1319i c1319i2 = new C1319i((V) this.n, (kotlin.coroutines.h) obj3, 1);
                c1319i2.m = (O) obj;
                return c1319i2.invokeSuspend(Unit.a);
            case 2:
                C1319i c1319i3 = new C1319i((kotlin.coroutines.h) obj3, (V) this.n, 2);
                c1319i3.l = (InterfaceC5002j) obj;
                c1319i3.m = obj2;
                return c1319i3.invokeSuspend(Unit.a);
            case 3:
                C1319i c1319i4 = new C1319i((com.quizlet.local.datastore.preferences.J) this.n, (kotlin.coroutines.h) obj3, 3);
                c1319i4.l = (InterfaceC5002j) obj;
                c1319i4.m = (Throwable) obj2;
                return c1319i4.invokeSuspend(Unit.a);
            case 4:
                C1319i c1319i5 = new C1319i((com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.G) this.n, (kotlin.coroutines.h) obj3, 4);
                c1319i5.l = (InterfaceC5002j) obj;
                c1319i5.m = (Throwable) obj2;
                return c1319i5.invokeSuspend(Unit.a);
            case 5:
                C1319i c1319i6 = new C1319i(this.n, (kotlin.coroutines.h) obj3, 5);
                c1319i6.l = (InterfaceC5002j) obj;
                c1319i6.m = (Throwable) obj2;
                return c1319i6.invokeSuspend(Unit.a);
            case 6:
                Object obj4 = ((kotlin.r) obj2).a;
                C1319i c1319i7 = new C1319i((Function2) this.n, (kotlin.coroutines.h) obj3);
                c1319i7.l = (InterfaceC5002j) obj;
                c1319i7.m = new kotlin.r(obj4);
                return c1319i7.invokeSuspend(Unit.a);
            case 7:
                C1319i c1319i8 = new C1319i((io.ktor.client.c) this.n, (kotlin.coroutines.h) obj3, 7);
                c1319i8.l = (io.ktor.util.pipeline.e) obj;
                c1319i8.m = obj2;
                return c1319i8.invokeSuspend(Unit.a);
            case 8:
                C1319i c1319i9 = new C1319i((Function2) this.n, (kotlin.coroutines.h) obj3, 8);
                c1319i9.l = (io.ktor.util.pipeline.e) obj;
                c1319i9.m = (io.ktor.client.statement.b) obj2;
                return c1319i9.invokeSuspend(Unit.a);
            case 9:
                C1319i c1319i10 = new C1319i((List) this.n, (kotlin.coroutines.h) obj3, 9);
                c1319i10.l = (io.ktor.client.plugins.api.g) obj;
                c1319i10.m = (io.ktor.client.request.c) obj2;
                return c1319i10.invokeSuspend(Unit.a);
            case 10:
                C1319i c1319i11 = new C1319i((io.ktor.client.plugins.api.c) this.n, (kotlin.coroutines.h) obj3, 10);
                c1319i11.l = (io.ktor.client.plugins.api.g) obj;
                c1319i11.m = (io.ktor.client.request.c) obj2;
                return c1319i11.invokeSuspend(Unit.a);
            case 11:
                C1319i c1319i12 = new C1319i((io.ktor.client.plugins.api.c) this.n, (kotlin.coroutines.h) obj3, 11);
                c1319i12.m = (io.ktor.client.request.c) obj;
                c1319i12.l = (Function1) obj2;
                return c1319i12.invokeSuspend(Unit.a);
            case 12:
                C1319i c1319i13 = new C1319i((kotlin.jvm.functions.e) this.n, (kotlin.coroutines.h) obj3, 12);
                c1319i13.m = (io.ktor.util.pipeline.e) obj;
                return c1319i13.invokeSuspend(Unit.a);
            case 13:
                C1319i c1319i14 = new C1319i((Function2) this.n, (kotlin.coroutines.h) obj3, 13);
                c1319i14.l = (InterfaceC5002j) obj;
                c1319i14.m = obj2;
                return c1319i14.invokeSuspend(Unit.a);
            case 14:
                C1319i c1319i15 = new C1319i((kotlin.coroutines.h) obj3, this.n, 14);
                c1319i15.l = (InterfaceC5002j) obj;
                c1319i15.m = (Object[]) obj2;
                return c1319i15.invokeSuspend(Unit.a);
            case 15:
                C1319i c1319i16 = new C1319i((kotlin.coroutines.h) obj3, this.n, 15);
                c1319i16.l = (InterfaceC5002j) obj;
                c1319i16.m = (Object[]) obj2;
                return c1319i16.invokeSuspend(Unit.a);
            default:
                C1319i c1319i17 = new C1319i((kotlin.jvm.functions.c) this.m, (kotlin.coroutines.h) obj3);
                c1319i17.l = (InterfaceC5002j) obj;
                c1319i17.n = (Object[]) obj2;
                return c1319i17.invokeSuspend(Unit.a);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:211:0x0470  */
    /* JADX WARN: Removed duplicated region for block: B:220:0x0488  */
    /* JADX WARN: Removed duplicated region for block: B:330:0x0678  */
    /* JADX WARN: Removed duplicated region for block: B:331:0x067b  */
    /* JADX WARN: Removed duplicated region for block: B:333:0x067e  */
    /* JADX WARN: Removed duplicated region for block: B:335:0x0684 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:344:0x0698  */
    /* JADX WARN: Removed duplicated region for block: B:345:0x069b  */
    /* JADX WARN: Removed duplicated region for block: B:347:0x069e  */
    /* JADX WARN: Removed duplicated region for block: B:356:0x06af  */
    /* JADX WARN: Removed duplicated region for block: B:357:0x06b4  */
    /* JADX WARN: Removed duplicated region for block: B:364:0x06e2  */
    /* JADX WARN: Removed duplicated region for block: B:366:0x06eb  */
    /* JADX WARN: Removed duplicated region for block: B:416:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:418:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r3v38, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    /* JADX WARN: Type inference failed for: r4v34, types: [java.lang.Object, kotlin.jvm.functions.c] */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r25) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 1910
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.paging.C1319i.invokeSuspend(java.lang.Object):java.lang.Object");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C1319i(kotlin.coroutines.h hVar, Object obj, int i) {
        super(3, hVar);
        this.j = i;
        this.n = obj;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public C1319i(Function2 function2, kotlin.coroutines.h hVar) {
        super(3, hVar);
        this.j = 6;
        this.n = (kotlin.coroutines.jvm.internal.i) function2;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1319i(kotlin.jvm.functions.c cVar, kotlin.coroutines.h hVar) {
        super(3, hVar);
        this.j = 16;
        this.m = cVar;
    }
}
