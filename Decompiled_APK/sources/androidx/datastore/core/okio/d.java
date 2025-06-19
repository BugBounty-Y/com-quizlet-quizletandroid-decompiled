package androidx.datastore.core.okio;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.r;
import okio.x;

/* loaded from: classes.dex */
public final class d extends r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ e b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ d(e eVar, int i) {
        super(0);
        this.a = i;
        this.b = eVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                e eVar = this.b;
                x xVar = (x) eVar.c.invoke();
                if (okio.internal.e.a(xVar) != -1) {
                    return com.quizlet.quizletandroid.ui.folder.logging.a.f(xVar.a.s(), true);
                }
                throw new IllegalStateException(("OkioStorage requires absolute paths, but did not get an absolute path from producePath = " + eVar.c + ", instead got " + xVar).toString());
            default:
                com.quizlet.shared.usecase.folderstudymaterials.b bVar = e.f;
                e eVar2 = this.b;
                synchronized (bVar) {
                    e.e.remove(((x) eVar2.d.getValue()).a.s());
                }
                return Unit.a;
        }
    }
}
