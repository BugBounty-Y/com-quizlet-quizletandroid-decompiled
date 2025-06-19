package androidx.compose.ui.draganddrop;

import androidx.compose.ui.input.pointer.h;
import androidx.compose.ui.node.p0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class d extends r implements Function1 {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ d(Object obj, int i) {
        super(1);
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                e eVar = (e) obj;
                if (!eVar.a.m) {
                    return p0.b;
                }
                eVar.n = null;
                return p0.a;
            case 1:
                ((h) obj).getClass();
                return Boolean.TRUE;
            default:
                android.support.v4.media.session.a.A(obj);
                throw null;
        }
    }
}
