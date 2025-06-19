package io.ktor.client.utils;

import java.util.concurrent.CancellationException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class a {
    public static final com.quizlet.quizletandroid.ui.login.di.a a = new com.quizlet.quizletandroid.ui.login.di.a(5);
    public static final com.quizlet.quizletandroid.ui.login.di.a b = new com.quizlet.quizletandroid.ui.login.di.a(5);
    public static final com.quizlet.quizletandroid.ui.login.di.a c = new com.quizlet.quizletandroid.ui.login.di.a(5);
    public static final com.quizlet.quizletandroid.ui.login.di.a d = new com.quizlet.quizletandroid.ui.login.di.a(5);
    public static final com.quizlet.quizletandroid.ui.login.di.a e = new com.quizlet.quizletandroid.ui.login.di.a(5);

    public static final Throwable a(Throwable th) {
        Intrinsics.checkNotNullParameter(th, "<this>");
        Throwable cause = th;
        while (true) {
            if (!(cause instanceof CancellationException)) {
                if (cause == null) {
                    break;
                }
                return cause;
            }
            CancellationException cancellationException = (CancellationException) cause;
            if (Intrinsics.b(cause, cancellationException.getCause())) {
                break;
            }
            cause = cancellationException.getCause();
        }
        return th;
    }
}
