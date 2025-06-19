package kotlinx.coroutines;

import java.util.concurrent.CancellationException;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: kotlinx.coroutines.t, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5035t {
    public final Object a;
    public final InterfaceC5024j b;
    public final kotlin.jvm.functions.c c;
    public final Object d;
    public final Throwable e;

    public C5035t(Object obj, InterfaceC5024j interfaceC5024j, kotlin.jvm.functions.c cVar, Object obj2, Throwable th) {
        this.a = obj;
        this.b = interfaceC5024j;
        this.c = cVar;
        this.d = obj2;
        this.e = th;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r8v2, types: [java.lang.Throwable] */
    public static C5035t a(C5035t c5035t, InterfaceC5024j interfaceC5024j, CancellationException cancellationException, int i) {
        Object obj = c5035t.a;
        if ((i & 2) != 0) {
            interfaceC5024j = c5035t.b;
        }
        InterfaceC5024j interfaceC5024j2 = interfaceC5024j;
        kotlin.jvm.functions.c cVar = c5035t.c;
        Object obj2 = c5035t.d;
        CancellationException cancellationException2 = cancellationException;
        if ((i & 16) != 0) {
            cancellationException2 = c5035t.e;
        }
        c5035t.getClass();
        return new C5035t(obj, interfaceC5024j2, cVar, obj2, cancellationException2);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C5035t)) {
            return false;
        }
        C5035t c5035t = (C5035t) obj;
        return Intrinsics.b(this.a, c5035t.a) && Intrinsics.b(this.b, c5035t.b) && Intrinsics.b(this.c, c5035t.c) && Intrinsics.b(this.d, c5035t.d) && Intrinsics.b(this.e, c5035t.e);
    }

    public final int hashCode() {
        Object obj = this.a;
        int iHashCode = (obj == null ? 0 : obj.hashCode()) * 31;
        InterfaceC5024j interfaceC5024j = this.b;
        int iHashCode2 = (iHashCode + (interfaceC5024j == null ? 0 : interfaceC5024j.hashCode())) * 31;
        kotlin.jvm.functions.c cVar = this.c;
        int iHashCode3 = (iHashCode2 + (cVar == null ? 0 : cVar.hashCode())) * 31;
        Object obj2 = this.d;
        int iHashCode4 = (iHashCode3 + (obj2 == null ? 0 : obj2.hashCode())) * 31;
        Throwable th = this.e;
        return iHashCode4 + (th != null ? th.hashCode() : 0);
    }

    public final String toString() {
        return "CompletedContinuation(result=" + this.a + ", cancelHandler=" + this.b + ", onCancellation=" + this.c + ", idempotentResume=" + this.d + ", cancelCause=" + this.e + ')';
    }

    public /* synthetic */ C5035t(Object obj, InterfaceC5024j interfaceC5024j, kotlin.jvm.functions.c cVar, CancellationException cancellationException, int i) {
        this(obj, (i & 2) != 0 ? null : interfaceC5024j, (i & 4) != 0 ? null : cVar, (Object) null, (i & 16) != 0 ? null : cancellationException);
    }
}
