package androidx.compose.runtime;

import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5023i0;
import kotlinx.coroutines.C5027k0;
import kotlinx.coroutines.InterfaceC5025j0;

/* renamed from: androidx.compose.runtime.y0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0838y0 implements kotlinx.coroutines.C, InterfaceC0834w0 {
    public static final C0796g e = new C0796g();
    public final CoroutineContext a;
    public final kotlin.coroutines.n b;
    public final C0838y0 c = this;
    public volatile CoroutineContext d;

    public C0838y0(CoroutineContext coroutineContext, kotlin.coroutines.n nVar) {
        this.a = coroutineContext;
        this.b = nVar;
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void a() {
        c();
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void b() {
        c();
    }

    public final void c() {
        synchronized (this.c) {
            try {
                CoroutineContext coroutineContext = this.d;
                if (coroutineContext == null) {
                    this.d = e;
                } else {
                    kotlinx.coroutines.E.h(coroutineContext, new J(0));
                }
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void d() {
    }

    @Override // kotlinx.coroutines.C
    public final CoroutineContext getCoroutineContext() {
        CoroutineContext coroutineContextPlus;
        CoroutineContext coroutineContext = this.d;
        if (coroutineContext == null || coroutineContext == e) {
            synchronized (this.c) {
                try {
                    coroutineContextPlus = this.d;
                    if (coroutineContextPlus == null) {
                        CoroutineContext coroutineContext2 = this.a;
                        coroutineContextPlus = coroutineContext2.plus(new C5027k0((InterfaceC5025j0) coroutineContext2.get(C5023i0.a))).plus(this.b);
                    } else if (coroutineContextPlus == e) {
                        CoroutineContext coroutineContext3 = this.a;
                        C5027k0 c5027k0 = new C5027k0((InterfaceC5025j0) coroutineContext3.get(C5023i0.a));
                        c5027k0.z(new J(0));
                        coroutineContextPlus = coroutineContext3.plus(c5027k0).plus(this.b);
                    }
                    this.d = coroutineContextPlus;
                    Unit unit = Unit.a;
                } catch (Throwable th) {
                    throw th;
                }
            }
            coroutineContext = coroutineContextPlus;
        }
        Intrinsics.d(coroutineContext);
        return coroutineContext;
    }
}
