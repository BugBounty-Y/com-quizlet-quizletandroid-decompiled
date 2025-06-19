package io.ktor.client.engine;

import androidx.compose.ui.text.font.o;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.u;
import kotlinx.coroutines.A0;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.B;
import kotlinx.coroutines.C5023i0;
import kotlinx.coroutines.C5027k0;
import kotlinx.coroutines.C5041z;
import kotlinx.coroutines.InterfaceC5034s;
import kotlinx.coroutines.O;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public abstract class f implements d {
    public static final /* synthetic */ AtomicIntegerFieldUpdater c = AtomicIntegerFieldUpdater.newUpdater(f.class, "closed");
    public final u a;
    public final u b;

    @NotNull
    private volatile /* synthetic */ int closed;

    public f() {
        Intrinsics.checkNotNullParameter("ktor-okhttp", "engineName");
        this.closed = 0;
        final int i = 0;
        this.a = kotlin.l.b(new Function0(this) { // from class: io.ktor.client.engine.e
            public final /* synthetic */ f b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                f fVar = this.b;
                switch (i) {
                    case 0:
                        ((io.ktor.client.engine.okhttp.f) fVar).d.getClass();
                        kotlinx.coroutines.scheduling.e eVar = O.a;
                        return kotlinx.coroutines.scheduling.d.b;
                    default:
                        return kotlin.coroutines.k.c(new o(C5041z.a, 13), new A0(null)).plus((AbstractC5040y) fVar.a.getValue()).plus(new B("ktor-okhttp-context"));
                }
            }
        });
        final int i2 = 1;
        this.b = kotlin.l.b(new Function0(this) { // from class: io.ktor.client.engine.e
            public final /* synthetic */ f b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                f fVar = this.b;
                switch (i2) {
                    case 0:
                        ((io.ktor.client.engine.okhttp.f) fVar).d.getClass();
                        kotlinx.coroutines.scheduling.e eVar = O.a;
                        return kotlinx.coroutines.scheduling.d.b;
                    default:
                        return kotlin.coroutines.k.c(new o(C5041z.a, 13), new A0(null)).plus((AbstractC5040y) fVar.a.getValue()).plus(new B("ktor-okhttp-context"));
                }
            }
        });
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        if (c.compareAndSet(this, 0, 1)) {
            CoroutineContext.Element element = getCoroutineContext().get(C5023i0.a);
            InterfaceC5034s interfaceC5034s = element instanceof InterfaceC5034s ? (InterfaceC5034s) element : null;
            if (interfaceC5034s == null) {
                return;
            }
            ((C5027k0) interfaceC5034s).k0();
        }
    }

    @Override // kotlinx.coroutines.C
    public CoroutineContext getCoroutineContext() {
        return (CoroutineContext) this.b.getValue();
    }
}
