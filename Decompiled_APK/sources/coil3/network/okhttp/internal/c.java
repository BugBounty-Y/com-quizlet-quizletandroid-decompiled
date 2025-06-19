package coil3.network.okhttp.internal;

import androidx.compose.runtime.snapshots.t;
import androidx.glance.appwidget.protobuf.Z;
import java.io.IOException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.p;
import kotlin.r;
import kotlinx.coroutines.C5028l;
import okhttp3.H;
import okhttp3.InterfaceC5076e;
import okhttp3.InterfaceC5077f;
import okhttp3.internal.connection.g;

/* loaded from: classes.dex */
public final class c implements InterfaceC5077f, Function1 {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;

    public /* synthetic */ c(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                try {
                    ((g) this.b).cancel();
                } catch (Throwable unused) {
                }
                break;
            default:
                com.quizlet.features.infra.folder.menu.data.b it2 = (com.quizlet.features.infra.folder.menu.data.b) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                Long lValueOf = Long.valueOf(it2.a);
                Boolean bool = Boolean.FALSE;
                t tVar = (t) this.b;
                boolean z = !((Boolean) tVar.getOrDefault(lValueOf, bool)).booleanValue();
                tVar.put(Long.valueOf(it2.a), Boolean.valueOf(z));
                ((Function2) this.c).invoke(it2, Boolean.valueOf(z));
                break;
        }
        return Unit.a;
    }

    @Override // okhttp3.InterfaceC5077f
    public void onFailure(InterfaceC5076e interfaceC5076e, IOException iOException) {
        if (((g) interfaceC5076e).o) {
            return;
        }
        C5028l c5028l = (C5028l) this.c;
        p pVar = r.b;
        c5028l.resumeWith(Z.b(iOException));
    }

    @Override // okhttp3.InterfaceC5077f
    public void onResponse(InterfaceC5076e interfaceC5076e, H h) {
        p pVar = r.b;
        ((C5028l) this.c).resumeWith(h);
    }
}
