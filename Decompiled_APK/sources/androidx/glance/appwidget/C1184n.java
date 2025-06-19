package androidx.glance.appwidget;

import android.content.Context;
import com.google.android.gms.internal.mlkit_vision_barcode.L6;
import com.quizlet.quizletandroid.ui.widgets.AbstractC4769b;
import com.quizlet.quizletandroid.ui.widgets.InterfaceC4768a;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.glance.appwidget.n, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1184n extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ AbstractC4769b k;
    public final /* synthetic */ Context l;
    public final /* synthetic */ C1162c m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1184n(Context context, C1162c c1162c, AbstractC4769b abstractC4769b, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = abstractC4769b;
        this.l = context;
        this.m = c1162c;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C1184n(this.l, this.m, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1184n) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
            return Unit.a;
        }
        androidx.glance.appwidget.protobuf.Z.e(obj);
        this.j = 1;
        AbstractC4769b abstractC4769b = this.k;
        abstractC4769b.getClass();
        Context applicationContext = this.l.getApplicationContext();
        Intrinsics.checkNotNullExpressionValue(applicationContext, "getApplicationContext(...)");
        abstractC4769b.b((InterfaceC4768a) L6.b(applicationContext, InterfaceC4768a.class), this);
        return aVar;
    }
}
