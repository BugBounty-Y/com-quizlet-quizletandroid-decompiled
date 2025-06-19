package timber.log;

import java.util.Arrays;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends b {
    @Override // timber.log.b
    public final void a(String str, Object... args) {
        Intrinsics.checkNotNullParameter(args, "args");
        for (b bVar : c.c) {
            bVar.a(str, Arrays.copyOf(args, args.length));
        }
    }

    @Override // timber.log.b
    public final void b(Throwable th) {
        for (b bVar : c.c) {
            bVar.b(th);
        }
    }

    @Override // timber.log.b
    public final void c(Throwable th, String str, Object... args) {
        Intrinsics.checkNotNullParameter(args, "args");
        for (b bVar : c.c) {
            bVar.c(th, str, Arrays.copyOf(args, args.length));
        }
    }

    @Override // timber.log.b
    public final void d(String str, Object... args) {
        Intrinsics.checkNotNullParameter(args, "args");
        for (b bVar : c.c) {
            bVar.d(str, Arrays.copyOf(args, args.length));
        }
    }

    @Override // timber.log.b
    public final void e(Throwable th) {
        for (b bVar : c.c) {
            bVar.e(th);
        }
    }

    @Override // timber.log.b
    public final void f(Throwable th, String str, Object... args) {
        Intrinsics.checkNotNullParameter(args, "args");
        for (b bVar : c.c) {
            bVar.f(th, str, Arrays.copyOf(args, args.length));
        }
    }

    @Override // timber.log.b
    public final void g(String str, Object... args) {
        Intrinsics.checkNotNullParameter(args, "args");
        for (b bVar : c.c) {
            bVar.g(str, Arrays.copyOf(args, args.length));
        }
    }

    @Override // timber.log.b
    public final void h(Throwable th) {
        for (b bVar : c.c) {
            bVar.h(th);
        }
    }

    @Override // timber.log.b
    public final void i(Throwable th, String str, Object... args) {
        Intrinsics.checkNotNullParameter(args, "args");
        for (b bVar : c.c) {
            bVar.i(th, str, Arrays.copyOf(args, args.length));
        }
    }

    @Override // timber.log.b
    public final void k(int i, String message, Throwable th) {
        Intrinsics.checkNotNullParameter(message, "message");
        throw new AssertionError();
    }

    @Override // timber.log.b
    public final void m(String str, Object... args) {
        Intrinsics.checkNotNullParameter(args, "args");
        for (b bVar : c.c) {
            bVar.m(str, Arrays.copyOf(args, args.length));
        }
    }

    @Override // timber.log.b
    public final void n(Throwable th, String str, Object... args) {
        Intrinsics.checkNotNullParameter(args, "args");
        for (b bVar : c.c) {
            bVar.n(th, str, Arrays.copyOf(args, args.length));
        }
    }

    @Override // timber.log.b
    public final void o(String str, Object... args) {
        Intrinsics.checkNotNullParameter(args, "args");
        for (b bVar : c.c) {
            bVar.o(str, Arrays.copyOf(args, args.length));
        }
    }

    @Override // timber.log.b
    public final void p(Throwable th) {
        for (b bVar : c.c) {
            bVar.p(th);
        }
    }

    @Override // timber.log.b
    public final void q(Throwable th, String str, Object... args) {
        Intrinsics.checkNotNullParameter(args, "args");
        for (b bVar : c.c) {
            bVar.q(th, str, Arrays.copyOf(args, args.length));
        }
    }
}
