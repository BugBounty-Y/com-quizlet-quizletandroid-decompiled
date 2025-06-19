package androidx.compose.animation;

import android.view.View;
import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.quizlet.quizletandroid.R;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class U extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ U(int i, Function1 function1) {
        super(1);
        this.a = i;
        this.b = function1;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        long j;
        switch (this.a) {
            case 0:
                return new androidx.compose.ui.unit.h(P5.b(0, ((Number) this.b.invoke(Integer.valueOf((int) (((androidx.compose.ui.unit.j) obj).a & 4294967295L)))).intValue()));
            case 1:
                return new androidx.compose.ui.unit.h(P5.b(0, ((Number) this.b.invoke(Integer.valueOf((int) (((androidx.compose.ui.unit.j) obj).a & 4294967295L)))).intValue()));
            case 2:
                throw d0.l(obj);
            case 3:
                androidx.compose.runtime.snapshots.l lVar = (androidx.compose.runtime.snapshots.l) obj;
                synchronized (androidx.compose.runtime.snapshots.m.b) {
                    j = androidx.compose.runtime.snapshots.m.d;
                    androidx.compose.runtime.snapshots.m.d = 1 + j;
                }
                return new androidx.compose.runtime.snapshots.g(j, lVar, this.b);
            default:
                Object tag = ((View) obj).getTag(R.id.binding_reference);
                Intrinsics.e(tag, "null cannot be cast to non-null type T of androidx.compose.ui.viewinterop.AndroidViewBindingKt.getBinding");
                this.b.invoke((androidx.viewbinding.a) tag);
                return Unit.a;
        }
    }
}
