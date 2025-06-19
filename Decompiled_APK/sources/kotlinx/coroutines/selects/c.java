package kotlinx.coroutines.selects;

import com.android.billingclient.api.C1472a;
import kotlin.jvm.internal.C4956o;
import kotlinx.coroutines.Q;
import kotlinx.coroutines.internal.q;

/* loaded from: classes3.dex */
public final class c {
    public final Object a;
    public final C4956o b;
    public final kotlin.jvm.functions.c c;
    public final C1472a d;
    public final kotlin.coroutines.jvm.internal.i e;
    public Object f;
    public int g = -1;
    public final /* synthetic */ e h;

    /* JADX WARN: Multi-variable type inference failed */
    public c(e eVar, Object obj, kotlin.jvm.functions.c cVar, kotlin.jvm.functions.c cVar2, C1472a c1472a, kotlin.coroutines.jvm.internal.i iVar, kotlinx.coroutines.channels.b bVar) {
        this.h = eVar;
        this.a = obj;
        this.b = (C4956o) cVar;
        this.c = cVar2;
        this.d = c1472a;
        this.e = iVar;
    }

    public final void a() {
        Object obj = this.f;
        if (obj instanceof q) {
            ((q) obj).h(this.g, this.h.a);
            return;
        }
        Q q = obj instanceof Q ? (Q) obj : null;
        if (q != null) {
            q.dispose();
        }
    }
}
