package okhttp3.internal.http2;

import java.io.IOException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class l extends okhttp3.internal.concurrent.a {
    public final /* synthetic */ int e;
    public final /* synthetic */ n f;
    public final /* synthetic */ int g;
    public final /* synthetic */ a h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ l(String str, n nVar, int i, a aVar, int i2) {
        super(str, true);
        this.e = i2;
        this.f = nVar;
        this.g = i;
        this.h = aVar;
    }

    @Override // okhttp3.internal.concurrent.a
    public final long a() throws IOException {
        switch (this.e) {
            case 0:
                y yVar = this.f.k;
                a errorCode = this.h;
                yVar.getClass();
                Intrinsics.checkNotNullParameter(errorCode, "errorCode");
                synchronized (this.f) {
                    this.f.y.remove(Integer.valueOf(this.g));
                    Unit unit = Unit.a;
                }
                return -1L;
            default:
                n nVar = this.f;
                try {
                    int i = this.g;
                    a statusCode = this.h;
                    nVar.getClass();
                    Intrinsics.checkNotNullParameter(statusCode, "statusCode");
                    nVar.w.p(i, statusCode);
                } catch (IOException e) {
                    nVar.d(e);
                }
                return -1L;
        }
    }
}
