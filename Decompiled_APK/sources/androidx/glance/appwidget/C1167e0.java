package androidx.glance.appwidget;

import android.util.Log;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.channels.ClosedSendChannelException;

/* renamed from: androidx.glance.appwidget.e0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1167e0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C1173h0 k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1167e0(C1173h0 c1173h0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c1173h0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C1167e0(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1167e0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        try {
            if (i == 0) {
                androidx.glance.appwidget.protobuf.Z.e(obj);
                C1173h0 c1173h0 = this.k;
                C1162c c1162c = new C1162c(c1173h0.b);
                this.j = 1;
                if (C1173h0.a(c1173h0, c1162c, this) == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                androidx.glance.appwidget.protobuf.Z.e(obj);
            }
            return Unit.a;
        } catch (ClosedSendChannelException e) {
            return new Integer(Log.e("GlanceRemoteViewService", "Error when trying to start session for list items", e));
        }
    }
}
