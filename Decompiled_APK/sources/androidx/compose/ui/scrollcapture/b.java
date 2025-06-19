package androidx.compose.ui.scrollcapture;

import android.graphics.Rect;
import android.view.ScrollCaptureSession;
import androidx.compose.ui.graphics.F;
import androidx.glance.appwidget.protobuf.Z;
import java.util.function.Consumer;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ f k;
    public final /* synthetic */ ScrollCaptureSession l;
    public final /* synthetic */ Rect m;
    public final /* synthetic */ Consumer n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(f fVar, ScrollCaptureSession scrollCaptureSession, Rect rect, Consumer consumer, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = fVar;
        this.l = scrollCaptureSession;
        this.m = rect;
        this.n = consumer;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new b(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            ScrollCaptureSession scrollCaptureSession = this.l;
            Rect rect = this.m;
            androidx.compose.ui.unit.i iVar = new androidx.compose.ui.unit.i(rect.left, rect.top, rect.right, rect.bottom);
            this.j = 1;
            obj = f.a(this.k, scrollCaptureSession, iVar, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        this.n.accept(F.x((androidx.compose.ui.unit.i) obj));
        return Unit.a;
    }
}
