package io.reactivex.rxjava3.internal.functions;

import androidx.emoji2.text.n;
import com.quizlet.infra.legacysyncengine.net.request.g;
import com.quizlet.quizletandroid.ui.profile.p;

/* loaded from: classes3.dex */
public abstract class d {
    public static final p a = new p(5);
    public static final n b = new n(5);
    public static final b c = new b();
    public static final g d = new g(2);
    public static final g e = new g(3);
    public static final com.quizlet.quizletandroid.ui.profile.data.b f = new com.quizlet.quizletandroid.ui.profile.data.b(5);

    public static void a(int i, String str) {
        if (i > 0) {
            return;
        }
        throw new IllegalArgumentException(str + " > 0 required but it was " + i);
    }
}
