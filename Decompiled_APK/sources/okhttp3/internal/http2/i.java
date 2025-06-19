package okhttp3.internal.http2;

import java.io.IOException;

/* loaded from: classes3.dex */
public final class i extends okhttp3.internal.concurrent.a {
    public final /* synthetic */ n e;
    public final /* synthetic */ int f;
    public final /* synthetic */ int g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(String str, n nVar, int i, int i2) {
        super(str, true);
        this.e = nVar;
        this.f = i;
        this.g = i2;
    }

    @Override // okhttp3.internal.concurrent.a
    public final long a() throws IOException {
        int i = this.f;
        int i2 = this.g;
        n nVar = this.e;
        nVar.getClass();
        try {
            nVar.w.l(i, i2, true);
            return -1L;
        } catch (IOException e) {
            nVar.d(e);
            return -1L;
        }
    }
}
