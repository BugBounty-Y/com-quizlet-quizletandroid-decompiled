package okhttp3.internal.http2;

import java.io.IOException;

/* loaded from: classes3.dex */
public final class m extends okhttp3.internal.concurrent.a {
    public final /* synthetic */ n e;
    public final /* synthetic */ int f;
    public final /* synthetic */ long g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(String str, n nVar, int i, long j) {
        super(str, true);
        this.e = nVar;
        this.f = i;
        this.g = j;
    }

    @Override // okhttp3.internal.concurrent.a
    public final long a() throws IOException {
        n nVar = this.e;
        try {
            nVar.w.q(this.f, this.g);
            return -1L;
        } catch (IOException e) {
            nVar.d(e);
            return -1L;
        }
    }
}
