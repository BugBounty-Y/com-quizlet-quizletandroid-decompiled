package okhttp3.internal.http1;

import com.google.android.gms.internal.ads.C2007ea;
import java.io.IOException;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.internal.connection.i;
import okio.A;
import okio.C5091h;
import okio.G;
import okio.I;
import okio.p;

/* loaded from: classes3.dex */
public abstract class a implements G {
    public final p a;
    public boolean b;
    public final /* synthetic */ C2007ea c;

    public a(C2007ea c2007ea) {
        this.c = c2007ea;
        this.a = new p(((A) c2007ea.a).a.h());
    }

    public final void a() {
        C2007ea c2007ea = this.c;
        int i = c2007ea.b;
        if (i == 6) {
            return;
        }
        if (i == 5) {
            C2007ea.i(c2007ea, this.a);
            c2007ea.b = 6;
        } else {
            throw new IllegalStateException("state: " + c2007ea.b);
        }
    }

    @Override // okio.G
    public long b0(C5091h sink, long j) throws IOException {
        C2007ea c2007ea = this.c;
        Intrinsics.checkNotNullParameter(sink, "sink");
        try {
            return ((A) c2007ea.a).b0(sink, j);
        } catch (IOException e) {
            ((i) c2007ea.d).k();
            a();
            throw e;
        }
    }

    @Override // okio.G
    public final I h() {
        return this.a;
    }
}
