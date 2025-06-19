package okhttp3;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.pubmatic.sdk.video.c;
import java.net.ProxySelector;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class z {
    public com.quizlet.data.repository.explanations.exercise.b a = new com.quizlet.data.repository.explanations.exercise.b(8);
    public com.quizlet.local.ormlite.models.term.b b = new com.quizlet.local.ormlite.models.term.b();
    public final ArrayList c = new ArrayList();
    public final ArrayList d = new ArrayList();
    public com.quizlet.quizletandroid.ui.setcreation.imageupload.a e;
    public boolean f;
    public o g;
    public boolean h;
    public boolean i;
    public n j;
    public o k;
    public ProxySelector l;
    public o m;
    public SocketFactory n;
    public SSLSocketFactory o;
    public X509TrustManager p;
    public List q;
    public List r;
    public okhttp3.internal.tls.c s;
    public C5079h t;
    public AbstractC3375o2 u;
    public int v;
    public int w;
    public int x;
    public long y;
    public com.quizlet.quizletandroid.ui.setcreation.managers.n z;

    public z() {
        Intrinsics.checkNotNullParameter(o.c, "<this>");
        this.e = new com.quizlet.quizletandroid.ui.setcreation.imageupload.a(22);
        this.f = true;
        o oVar = InterfaceC5073b.a;
        this.g = oVar;
        this.h = true;
        this.i = true;
        this.j = n.a;
        this.k = o.b;
        this.m = oVar;
        SocketFactory socketFactory = SocketFactory.getDefault();
        Intrinsics.checkNotNullExpressionValue(socketFactory, "getDefault()");
        this.n = socketFactory;
        this.q = A.B;
        this.r = A.A;
        this.s = okhttp3.internal.tls.c.a;
        this.t = C5079h.c;
        this.v = c.a.DEFAULT_MEDIA_URI_TIMEOUT;
        this.w = c.a.DEFAULT_MEDIA_URI_TIMEOUT;
        this.x = c.a.DEFAULT_MEDIA_URI_TIMEOUT;
        this.y = 1024L;
    }

    public final void a(u interceptor) {
        Intrinsics.checkNotNullParameter(interceptor, "interceptor");
        this.c.add(interceptor);
    }

    public final A b() {
        return new A(this);
    }

    public final void c(long j, TimeUnit unit) {
        Intrinsics.checkNotNullParameter(unit, "unit");
        this.w = okhttp3.internal.b.b("timeout", j, unit);
    }
}
