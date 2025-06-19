package okhttp3.internal.http2;

import java.io.IOException;
import kotlin.jvm.internal.Intrinsics;
import okio.C5091h;

/* loaded from: classes3.dex */
public final class j extends okhttp3.internal.concurrent.a {
    public final /* synthetic */ n e;
    public final /* synthetic */ int f;
    public final /* synthetic */ C5091h g;
    public final /* synthetic */ int h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(String str, n nVar, int i, C5091h c5091h, int i2, boolean z) {
        super(str, true);
        this.e = nVar;
        this.f = i;
        this.g = c5091h;
        this.h = i2;
    }

    @Override // okhttp3.internal.concurrent.a
    public final long a() {
        try {
            y yVar = this.e.k;
            C5091h source = this.g;
            int i = this.h;
            yVar.getClass();
            Intrinsics.checkNotNullParameter(source, "source");
            source.skip(i);
            this.e.w.p(this.f, a.CANCEL);
            synchronized (this.e) {
                this.e.y.remove(Integer.valueOf(this.f));
            }
            return -1L;
        } catch (IOException unused) {
            return -1L;
        }
    }
}
