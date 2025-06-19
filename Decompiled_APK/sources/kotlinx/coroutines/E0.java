package kotlinx.coroutines;

/* loaded from: classes3.dex */
public final class E0 extends kotlinx.coroutines.internal.p implements Runnable {
    public final long e;

    public E0(long j, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar, cVar.getContext());
        this.e = j;
    }

    @Override // kotlinx.coroutines.q0
    public final String W() {
        StringBuilder sb = new StringBuilder();
        sb.append(super.W());
        sb.append("(timeMillis=");
        return androidx.compose.animation.d0.q(sb, this.e, ')');
    }

    @Override // java.lang.Runnable
    public final void run() {
        E.q(this.c);
        x(new TimeoutCancellationException(android.support.v4.media.session.a.g(this.e, " ms", new StringBuilder("Timed out waiting for ")), this));
    }
}
