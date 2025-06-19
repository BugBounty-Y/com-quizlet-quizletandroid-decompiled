package okhttp3;

import java.io.File;
import kotlin.jvm.internal.Intrinsics;
import okio.AbstractC5085b;
import okio.C5087d;
import okio.InterfaceC5092i;

/* loaded from: classes3.dex */
public final class D extends F {
    public final /* synthetic */ int a;
    public final w b;
    public final Object c;

    public /* synthetic */ D(w wVar, Object obj, int i) {
        this.a = i;
        this.b = wVar;
        this.c = obj;
    }

    @Override // okhttp3.F
    public final long a() {
        switch (this.a) {
            case 0:
                return ((File) this.c).length();
            case 1:
                return ((okio.k) this.c).d();
            default:
                return ((F) this.c).a();
        }
    }

    @Override // okhttp3.F
    public final w b() {
        switch (this.a) {
        }
        return this.b;
    }

    @Override // okhttp3.F
    public final void d(InterfaceC5092i sink) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(sink, "sink");
                C5087d c5087dI = AbstractC5085b.i((File) this.c);
                try {
                    sink.M(c5087dI);
                    c5087dI.close();
                    return;
                } finally {
                }
            case 1:
                Intrinsics.checkNotNullParameter(sink, "sink");
                sink.Z((okio.k) this.c);
                return;
            default:
                ((F) this.c).d(sink);
                return;
        }
    }

    public D(F f, w wVar) {
        this.a = 2;
        this.c = f;
        this.b = wVar;
    }
}
