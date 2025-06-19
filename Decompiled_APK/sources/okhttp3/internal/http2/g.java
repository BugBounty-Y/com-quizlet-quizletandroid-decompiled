package okhttp3.internal.http2;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class g {
    public static final f a = new f();

    public void a(n connection, z settings) {
        Intrinsics.checkNotNullParameter(connection, "connection");
        Intrinsics.checkNotNullParameter(settings, "settings");
    }

    public abstract void b(v vVar);
}
