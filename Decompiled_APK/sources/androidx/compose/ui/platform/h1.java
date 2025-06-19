package androidx.compose.ui.platform;

import android.view.View;
import androidx.compose.runtime.C0818r0;
import androidx.compose.runtime.C0832v0;
import com.quizlet.quizletandroid.R;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class h1 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C0832v0 k;
    public final /* synthetic */ View l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h1(C0832v0 c0832v0, View view, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0832v0;
        this.l = view;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new h1(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h1) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        C0832v0 c0832v0 = this.k;
        View view = this.l;
        try {
            if (i == 0) {
                androidx.glance.appwidget.protobuf.Z.e(obj);
                this.j = 1;
                Object objQ = kotlinx.coroutines.flow.e0.q(c0832v0.u, new C0818r0(2, null), this);
                if (objQ != obj2) {
                    objQ = Unit.a;
                }
                if (objQ == obj2) {
                    return obj2;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                androidx.glance.appwidget.protobuf.Z.e(obj);
            }
            return Unit.a;
        } finally {
            if (p1.b(view) == c0832v0) {
                view.setTag(R.id.androidx_compose_ui_view_composition_context, null);
            }
        }
    }
}
