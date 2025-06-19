package okhttp3.internal.connection;

import androidx.compose.material.ripple.r;
import androidx.constraintlayout.core.motion.utils.l;
import java.io.IOException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.A;
import okhttp3.H;
import okhttp3.o;
import okhttp3.t;
import okhttp3.u;

/* loaded from: classes3.dex */
public final class a implements u {
    public static final a a = new a();

    @Override // okhttp3.u
    public final H intercept(t chain) throws IOException {
        Intrinsics.checkNotNullParameter(chain, "chain");
        okhttp3.internal.http.f chain2 = (okhttp3.internal.http.f) chain;
        g call = chain2.a;
        call.getClass();
        Intrinsics.checkNotNullParameter(chain2, "chain");
        synchronized (call) {
            if (!call.n) {
                throw new IllegalStateException("released");
            }
            if (call.m) {
                throw new IllegalStateException("Check failed.");
            }
            if (call.l) {
                throw new IllegalStateException("Check failed.");
            }
            Unit unit = Unit.a;
        }
        l finder = call.h;
        Intrinsics.d(finder);
        A client = call.a;
        Intrinsics.checkNotNullParameter(client, "client");
        Intrinsics.checkNotNullParameter(chain2, "chain");
        try {
            int i = chain2.f;
            int i2 = chain2.g;
            int i3 = chain2.h;
            client.getClass();
            okhttp3.internal.http.d codec = finder.d(i, i2, i3, client.f, !Intrinsics.b(chain2.e.b, "GET")).j(client, chain2);
            o eventListener = o.c;
            Intrinsics.checkNotNullParameter(call, "call");
            Intrinsics.checkNotNullParameter(eventListener, "eventListener");
            Intrinsics.checkNotNullParameter(finder, "finder");
            Intrinsics.checkNotNullParameter(codec, "codec");
            r rVar = new r();
            rVar.b = call;
            rVar.c = finder;
            rVar.d = codec;
            rVar.e = codec.e();
            call.k = rVar;
            call.p = rVar;
            synchronized (call) {
                call.l = true;
                call.m = true;
            }
            if (call.o) {
                throw new IOException("Canceled");
            }
            return okhttp3.internal.http.f.a(chain2, 0, rVar, null, 0, 0, 0, 61).b(chain2.e);
        } catch (IOException e) {
            finder.f(e);
            throw new RouteException(e);
        } catch (RouteException e2) {
            finder.f(e2.b);
            throw e2;
        }
    }
}
