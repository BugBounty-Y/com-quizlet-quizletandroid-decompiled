package timber.log;

import androidx.compose.animation.d0;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.util.Arrays;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class b {
    public final ThreadLocal a = new ThreadLocal();

    public void a(String str, Object... args) {
        Intrinsics.checkNotNullParameter(args, "args");
        l(3, null, str, Arrays.copyOf(args, args.length));
    }

    public void b(Throwable th) {
        l(3, th, null, new Object[0]);
    }

    public void c(Throwable th, String str, Object... args) {
        Intrinsics.checkNotNullParameter(args, "args");
        l(3, th, str, Arrays.copyOf(args, args.length));
    }

    public void d(String str, Object... args) {
        Intrinsics.checkNotNullParameter(args, "args");
        l(6, null, str, Arrays.copyOf(args, args.length));
    }

    public void e(Throwable th) {
        l(6, th, null, new Object[0]);
    }

    public void f(Throwable th, String str, Object... args) {
        Intrinsics.checkNotNullParameter(args, "args");
        l(6, th, str, Arrays.copyOf(args, args.length));
    }

    public void g(String str, Object... args) {
        Intrinsics.checkNotNullParameter(args, "args");
        l(4, null, str, Arrays.copyOf(args, args.length));
    }

    public void h(Throwable th) {
        l(4, th, null, new Object[0]);
    }

    public void i(Throwable th, String str, Object... args) {
        Intrinsics.checkNotNullParameter(args, "args");
        l(4, th, str, Arrays.copyOf(args, args.length));
    }

    public boolean j(int i) {
        return true;
    }

    public abstract void k(int i, String str, Throwable th);

    public final void l(int i, Throwable th, String message, Object... args) {
        ThreadLocal threadLocal = this.a;
        if (((String) threadLocal.get()) != null) {
            threadLocal.remove();
        }
        if (j(i)) {
            if (message != null && message.length() != 0) {
                if (args.length != 0) {
                    Intrinsics.checkNotNullParameter(message, "message");
                    Intrinsics.checkNotNullParameter(args, "args");
                    Object[] objArrCopyOf = Arrays.copyOf(args, args.length);
                    message = d0.s(objArrCopyOf, objArrCopyOf.length, message, "java.lang.String.format(this, *args)");
                }
                if (th != null) {
                    StringBuilder sb = new StringBuilder();
                    sb.append((Object) message);
                    sb.append('\n');
                    StringWriter stringWriter = new StringWriter(256);
                    PrintWriter printWriter = new PrintWriter((Writer) stringWriter, false);
                    th.printStackTrace(printWriter);
                    printWriter.flush();
                    String string = stringWriter.toString();
                    Intrinsics.checkNotNullExpressionValue(string, "sw.toString()");
                    sb.append(string);
                    message = sb.toString();
                }
            } else {
                if (th == null) {
                    return;
                }
                StringWriter stringWriter2 = new StringWriter(256);
                PrintWriter printWriter2 = new PrintWriter((Writer) stringWriter2, false);
                th.printStackTrace(printWriter2);
                printWriter2.flush();
                message = stringWriter2.toString();
                Intrinsics.checkNotNullExpressionValue(message, "sw.toString()");
            }
            k(i, message, th);
        }
    }

    public void m(String str, Object... args) {
        Intrinsics.checkNotNullParameter(args, "args");
        l(2, null, str, Arrays.copyOf(args, args.length));
    }

    public void n(Throwable th, String str, Object... args) {
        Intrinsics.checkNotNullParameter(args, "args");
        l(2, th, str, Arrays.copyOf(args, args.length));
    }

    public void o(String str, Object... args) {
        Intrinsics.checkNotNullParameter(args, "args");
        l(5, null, str, Arrays.copyOf(args, args.length));
    }

    public void p(Throwable th) {
        l(5, th, null, new Object[0]);
    }

    public void q(Throwable th, String str, Object... args) {
        Intrinsics.checkNotNullParameter(args, "args");
        l(5, th, str, Arrays.copyOf(args, args.length));
    }
}
