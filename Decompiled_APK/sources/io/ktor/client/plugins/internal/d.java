package io.ktor.client.plugins.internal;

import io.ktor.utils.io.A;
import io.ktor.utils.io.k;
import io.ktor.utils.io.n;
import io.ktor.utils.io.w;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;
import kotlinx.coroutines.C4977c0;
import kotlinx.coroutines.O;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class d {
    public static final /* synthetic */ AtomicReferenceFieldUpdater b = AtomicReferenceFieldUpdater.newUpdater(d.class, Object.class, "content");
    public final n a;

    @NotNull
    private volatile /* synthetic */ Object content;

    public d(n origin) {
        Intrinsics.checkNotNullParameter(origin, "origin");
        this.a = origin;
        this.content = null;
    }

    public final n a() throws Throwable {
        if (this.a.c() != null) {
            Throwable thC = this.a.c();
            Intrinsics.d(thC);
            throw thC;
        }
        J j = new J();
        Object obj = this.content;
        j.a = obj;
        C4977c0 c4977c0 = C4977c0.a;
        if (obj == null) {
            b bVar = new b(this);
            j.a = bVar;
            AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = b;
            while (!atomicReferenceFieldUpdater.compareAndSet(this, null, bVar)) {
                if (atomicReferenceFieldUpdater.get(this) != null) {
                    j.a = this.content;
                }
            }
            b bVar2 = (b) j.a;
            bVar2.getClass();
            A aB = w.b(c4977c0, O.b, new a(bVar2.c, bVar2, null), 2);
            Intrinsics.checkNotNullParameter(aB, "<set-?>");
            bVar2.b = aB;
            return (k) aB.b;
        }
        return (k) w.b(c4977c0, null, new c(j, null), 3).b;
    }
}
